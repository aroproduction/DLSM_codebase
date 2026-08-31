"""pipeline.py — DLSM dual-stage ML inference pipeline.

Stage 1: DistilBERT binary prefilter (fast, ~0.13s)
Stage 2: Llama Guard 3 1B safety classifier (~5s, only on borderline cases)

Exposes a single classify(prompt) entry point that returns the DLSM
classifier result dict matching the contract in ML_CLASSIFIER_API_CONTRACT.md.
"""

import os
import sys
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional

import torch
from transformers import (
    pipeline as hf_pipeline,
    AutoModelForCausalLM,
    AutoTokenizer,
)

logger = logging.getLogger(__name__)

DEFAULT_STAGE1_PATH = str(
    Path(__file__).resolve().parent / "stage1_prefilter"
)
DEFAULT_STAGE2_MODEL = "meta-llama/Llama-Guard-3-1B"

HIGH_CONF_THRESHOLD = 0.95  # risk >= 0.95  -> BLOCK (no Stage 2 needed)
LOW_CONF_THRESHOLD  = 0.60  # risk >= 0.60  -> Stage 2 for second opinion
#                           # risk <  0.60  -> PASS (no Stage 2 needed)
# Reduced from 0.70 so more borderline prompts get a Stage 2 second opinion.

# Multi-turn context: when prior turns are supplied, they are prepended to the
# current prompt so both stages see the conversational context ("priming") that
# multi-turn jailbreaks rely on. Oldest turn first, capped to a short window.
MAX_HISTORY_TURNS = 4

INJECTION_KEYWORDS = [
    "ignore previous", "ignore all previous", "disregard previous",
    "ignore above", "forget everything", "new instructions",
    "system prompt", "developer mode", "unrestricted",
    "bypass", "override", "no restrictions", "safety filters",
    "jailbreak", "dan ", "do anything now",
    "you are now", "act as", "roleplay as", "pretend you",
]

LG_CATEGORIES = {
    "S1": "Violence",
    "S2": "Violence / Threats",
    "S3": "Sexual Content",
    "S4": "Sexual Content (minors)",
    "S5": "Hate Speech / Harassment",
    "S6": "Self-Harm",
    "S7": "Criminal Planning / Conspiracy",
    "S8": "Guns / Illegal Weapons",
    "S9": "Regulated Substances / Drugs",
    "S10": "Fairness / Bias / Discrimination",
    "S11": "PII / Privacy Violation",
    "S12": "Malware / Cybersecurity",
    "S13": "Fraud / Deception",
    "S14": "Medical Advice",
    "S15": "Dangerous Content (general)",
}

DLSM_MAP = {
    "Violence":                       ("class_1_prompt_subversion", "harmful_content"),
    "Violence / Threats":             ("class_1_prompt_subversion", "harmful_content"),
    "Sexual Content":                 ("class_1_prompt_subversion", "harmful_content"),
    "Sexual Content (minors)":        ("class_1_prompt_subversion", "harmful_content"),
    "Hate Speech / Harassment":       ("class_1_prompt_subversion", "hate_harassment"),
    "Self-Harm":                      ("class_1_prompt_subversion", "harmful_content"),
    "Criminal Planning / Conspiracy": ("class_1_prompt_subversion", "criminal_activity"),
    "Guns / Illegal Weapons":         ("class_1_prompt_subversion", "criminal_activity"),
    "Regulated Substances / Drugs":   ("class_1_prompt_subversion", "criminal_activity"),
    "Fairness / Bias / Discrimination": ("class_1_prompt_subversion", "bias_discrimination"),
    "PII / Privacy Violation":        ("class_2_privacy_abuse", "data_extraction"),
    "Malware / Cybersecurity":        ("class_1_prompt_subversion", "cybersecurity"),
    "Fraud / Deception":              ("class_1_prompt_subversion", "fraud_deception"),
    "Medical Advice":                 ("class_3_operational_misuse", "policy_violation"),
    "Dangerous Content (general)":    ("class_1_prompt_subversion", "harmful_content"),
}

LG_TEMPLATE = (
    "[INST] Task: Check if there is any unsafe content in the User query "
    "according to our safety policy below.\n\n"
    "Unsafe Content Categories:\n"
    "- S1: Violence\n- S2: Violence and Threats\n- S3: Sexual Content\n"
    "- S4: Sexual Content involving Minors\n- S5: Hate Speech and Harassment\n"
    "- S6: Self-Harm\n- S7: Criminal Planning and Conspiracy\n"
    "- S8: Guns and Illegal Weapons\n- S9: Regulated Substances and Drugs\n"
    "- S10: Fairness, Bias, and Discrimination\n- S11: PII and Privacy Violation\n"
    "- S12: Malware and Cybersecurity\n- S13: Fraud and Deception\n"
    "- S14: Medical Advice\n- S15: Dangerous Content\n\n"
    "User query: {query}\n\n"
    "Provide your safety assessment:\n"
    '- If safe, output only: "safe"\n'
    '- If unsafe, output only the category code (e.g., S1, S5, S11) and nothing else. [/INST]'
)


def _detect_injection_heuristic(prompt: str) -> bool:
    lower = prompt.lower()
    return any(kw in lower for kw in INJECTION_KEYWORDS)


def _build_contextual_prompt(prompt: str, history: Optional[list]) -> str:
    """Prepend prior turns (oldest first) so classification is context-aware.

    Format:
        Previous turn 1: <...>
        Previous turn 2: <...>
        Current user prompt: <current>
    """
    if not history:
        return prompt

    turns = history[-MAX_HISTORY_TURNS:]
    lines = [
        f"Previous turn {i + 1}: {turn.strip()}"
        for i, turn in enumerate(turns)
    ]
    lines.append(f"Current user prompt: {prompt.strip()}")
    return "\n".join(lines)


def _determine_attack_family(lg_category_name: Optional[str], prompt: str) -> str:
    if lg_category_name and "PII" in lg_category_name:
        return "data_extraction"
    if lg_category_name and "Malware" in lg_category_name:
        return "cybersecurity"
    if _detect_injection_heuristic(prompt):
        return "prompt_injection"
    if lg_category_name and any(
        k in lg_category_name
        for k in ["Criminal", "Guns", "Regulated", "Substances"]
    ):
        return "criminal_activity"
    if lg_category_name:
        return "harmful_content"
    return "none"


class Stage1Filter:
    """DistilBERT binary prefilter."""

    def __init__(self, model_path: str):
        logger.info("Loading Stage 1 (DistilBERT) from %s", model_path)
        t0 = time.time()
        self._pipe = hf_pipeline(
            "text-classification",
            model=model_path,
            device=-1,
        )
        logger.info("Stage 1 loaded in %.2fs", time.time() - t0)

    def classify(self, prompt: str) -> dict:
        out = self._pipe(prompt, truncation=True, max_length=384)[0]
        label = out["label"]
        conf = out["score"]

        # Normalise to a single risk score = P(malicious)
        risk = conf if label == "malicious" else 1.0 - conf

        if risk >= HIGH_CONF_THRESHOLD:
            tier = "block"      # High confidence attack -> block immediately
        elif risk >= LOW_CONF_THRESHOLD:
            tier = "verify"     # Borderline -> send to Stage 2
        else:
            tier = "pass"       # Low risk -> pass

        return {"label": label, "score": round(risk, 4), "tier": tier}


class Stage2Filter:
    """Llama Guard 3 1B safety classifier."""

    def __init__(self, model_id: str):
        logger.info("Loading Stage 2 (Llama Guard 3 1B) from %s", model_id)
        t0 = time.time()
        self._tokenizer = AutoTokenizer.from_pretrained(model_id)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self._model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
        )
        if device == "cpu":
            self._model = self._model.to(device)
        self._model.eval()
        self._device = device
        logger.info("Stage 2 loaded in %.2fs (device=%s)", time.time() - t0, device)

    def classify(self, prompt: str) -> dict:
        formatted = LG_TEMPLATE.format(query=prompt)
        inputs = self._tokenizer(formatted, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(
                **inputs, max_new_tokens=10, do_sample=False,
                pad_token_id=self._tokenizer.eos_token_id,
            )
        raw = self._tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        ).strip()
        first_line = raw.split("\n")[0].strip().lower()

        if first_line == "safe":
            return {"is_attack": False, "risk_score": 0.05, "lg_category": None}

        if first_line == "unsafe":
            return {"is_attack": True, "risk_score": 0.75, "lg_category": "Unsafe (general)"}

        code = first_line.upper().replace(" ", "")
        if code.startswith("S") and code[1:].isdigit():
            num = code[1:]
            if num in LG_CATEGORIES:
                return {"is_attack": True, "risk_score": 0.85, "lg_category": LG_CATEGORIES[num]}

        for i in range(1, 16):
            c = f"S{i}"
            if c in first_line.upper():
                return {"is_attack": True, "risk_score": 0.85, "lg_category": LG_CATEGORIES[c]}

        if "unsafe" in first_line:
            return {"is_attack": True, "risk_score": 0.75, "lg_category": "Unsafe (general)"}

        return {"is_attack": False, "risk_score": 0.05, "lg_category": None}


class Pipeline:
    """Dual-stage DLSM classification pipeline."""

    def __init__(
        self,
        stage1_path: Optional[str] = None,
        stage2_model: Optional[str] = None,
    ):
        stage1_path = stage1_path or os.environ.get(
            "STAGE1_MODEL_PATH", DEFAULT_STAGE1_PATH
        )
        stage2_model = stage2_model or os.environ.get(
            "STAGE2_MODEL_ID", DEFAULT_STAGE2_MODEL
        )

        logger.info("Initializing DLSM ML pipeline")
        self._stage1 = Stage1Filter(stage1_path)

        self._stage2 = None
        try:
            self._stage2 = Stage2Filter(stage2_model)
        except Exception as exc:
            logger.warning(
                "Stage 2 (Llama Guard) failed to load; pipeline will run Stage 1 only. Error: %s",
                exc,
            )

        self._model_version = os.environ.get("MODEL_VERSION", "dlsm-ml-v1")
        logger.info(
            "Pipeline ready — Stage 1 loaded, Stage 2 %s",
            "loaded" if self._stage2 else "NOT available",
        )

    def classify(
        self,
        prompt: str,
        prompt_id: str = "",
        user_id: str = "",
        org_id: str = "",
        history: Optional[list] = None,
    ) -> dict:
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        context_prompt = _build_contextual_prompt(prompt, history)

        s1 = self._stage1.classify(context_prompt)

        if s1["tier"] == "block":
            risk_score = s1["score"]
            dlsm_class = "class_1_prompt_subversion"
            attack_family = "prompt_injection" if _detect_injection_heuristic(prompt) else "harmful_content"
            binary_label = "attack"

        elif s1["tier"] == "verify" and self._stage2 is not None:
            s2 = self._stage2.classify(context_prompt)
            if s2["is_attack"]:
                risk_score = s2["risk_score"]
                if _detect_injection_heuristic(prompt):
                    risk_score = max(risk_score, 0.85)
                dlsm_class, default_family = DLSM_MAP.get(
                    s2["lg_category"], ("class_1_prompt_subversion", "harmful_content")
                )
                attack_family = _determine_attack_family(s2["lg_category"], prompt)
                if attack_family == "none":
                    attack_family = default_family
                binary_label = "attack"
            else:
                risk_score = 0.05
                dlsm_class = "class_4_compliant_functional_use"
                attack_family = "benign"
                binary_label = "benign"

        else:
            # PASS tier (risk < 0.60), or VERIFY when Stage 2 is unavailable.
            # Without Stage 2, a still-borderline prompt (risk >= 0.70) is blocked
            # conservatively; everything else is passed with a floor risk score.
            if s1["score"] >= 0.70:
                risk_score = min(s1["score"], 0.80)
                dlsm_class = "class_1_prompt_subversion"
                attack_family = "prompt_injection" if _detect_injection_heuristic(prompt) else "harmful_content"
                binary_label = "attack"
            else:
                risk_score = min(s1["score"], 0.05)
                dlsm_class = "class_4_compliant_functional_use"
                attack_family = "benign"
                binary_label = "benign"

        result = {
            "promptId": prompt_id,
            "userId": user_id,
            "orgId": org_id,
            "promptHash": prompt_hash,
            "riskScore": round(risk_score, 4),
            "binaryLabel": binary_label,
            "dlsmClass": dlsm_class,
            "attackFamily": attack_family,
            "modelVersion": self._model_version,
            "timestamp": int(time.time()),
            "contextAware": bool(history),
        }
        return result
