"""stage2_filter.py -- Llama Guard 3 1B based DLSM Stage 2 classifier.

Produces the exact JSON format expected by the consortium system:
{
  "promptId", "userId", "orgId", "promptHash",
  "riskScore", "binaryLabel", "dlsmClass", "attackFamily",
  "modelVersion", "timestamp"
}

Usage:
    # Single prompt via CLI
    python stage2_filter.py --prompt "Ignore previous instructions..." --prompt-id req-001 --user-id Org1:user1 --org-id Org1

    # From file (one prompt per line)
    python stage2_filter.py --input-file prompts.txt

    # As a module
    from stage2_filter import Stage2Filter
    f = Stage2Filter()
    result = f.classify("some prompt", prompt_id="req-001", user_id="u1", org_id="Org1")
"""

import os
import sys
import json
import time
import hashlib
import argparse
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# ─────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────
MODEL_ID = "meta-llama/Llama-Guard-3-1B"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MAX_NEW_TOKENS = 128

# ─────────────────────────────────────────────────────────────────
# Llama Guard hazard categories (from Meta's taxonomy)
# ─────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────
# DLSM taxonomy mapping  (LG category -> DLSM class + attackFamily)
# ─────────────────────────────────────────────────────────────────
DLSM_MAP = {
    "Violence":              ("class_1_prompt_subversion", "harmful_content"),
    "Violence / Threats":    ("class_1_prompt_subversion", "harmful_content"),
    "Sexual Content":        ("class_1_prompt_subversion", "harmful_content"),
    "Sexual Content (minors)": ("class_1_prompt_subversion", "harmful_content"),
    "Hate Speech / Harassment": ("class_1_prompt_subversion", "hate_harassment"),
    "Self-Harm":             ("class_1_prompt_subversion", "harmful_content"),
    "Criminal Planning / Conspiracy": ("class_1_prompt_subversion", "criminal_activity"),
    "Guns / Illegal Weapons": ("class_1_prompt_subversion", "criminal_activity"),
    "Regulated Substances / Drugs": ("class_1_prompt_subversion", "criminal_activity"),
    "Fairness / Bias / Discrimination": ("class_1_prompt_subversion", "bias_discrimination"),
    "PII / Privacy Violation": ("class_2_data_privacy_abuse", "data_extraction"),
    "Malware / Cybersecurity": ("class_1_prompt_subversion", "cybersecurity"),
    "Fraud / Deception":     ("class_1_prompt_subversion", "fraud_deception"),
    "Medical Advice":        ("class_3_operational_misuse", "policy_violation"),
    "Dangerous Content (general)": ("class_1_prompt_subversion", "harmful_content"),
}

# Prompt injection / jailbreak heuristic keywords for attackFamily override
INJECTION_KEYWORDS = [
    "ignore previous", "ignore all previous", "disregard previous",
    "ignore above", "forget everything", "new instructions",
    "system prompt", "developer mode", "unrestricted",
    "bypass", "override", "no restrictions", "safety filters",
    "jailbreak", "dan ", "do anything now",
    "you are now", "act as", "roleplay as", "pretend you",
]

# ─────────────────────────────────────────────────────────────────
# Llama Guard prompt template
# ─────────────────────────────────────────────────────────────────
LG_PROMPT_TEMPLATE = """[INST] Task: Check if there is any unsafe content in the User query according to our safety policy below.

Unsafe Content Categories:
- S1: Violence
- S2: Violence and Threats
- S3: Sexual Content
- S4: Sexual Content involving Minors
- S5: Hate Speech and Harassment
- S6: Self-Harm
- S7: Criminal Planning and Conspiracy
- S8: Guns and Illegal Weapons
- S9: Regulated Substances and Drugs
- S10: Fairness, Bias, and Discrimination
- S11: PII and Privacy Violation
- S12: Malware and Cybersecurity
- S13: Fraud and Deception
- S14: Medical Advice
- S15: Dangerous Content

User query: {query}

Provide your safety assessment:
- If safe, output only: "safe"
- If unsafe, output only the category code (e.g., S1, S5, S11) and nothing else. [/INST]"""


class Stage2Filter:
    """Llama Guard 3 1B based Stage 2 classifier for DLSM."""

    def __init__(self, model_id: str = MODEL_ID, device: str = DEVICE):
        print(f"Loading Llama Guard 3 1B from: {model_id}")
        t0 = time.time()
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
        )
        if device == "cpu":
            self.model = self.model.to(device)
        self.model.eval()
        print(f"Model loaded in {time.time() - t0:.2f}s  (device={device})")

    # ── Core classification ─────────────────────────────────────
    def _query_lg(self, prompt: str) -> str:
        """Send prompt to Llama Guard and return raw response.

        LG outputs a single token: 'safe' or 'S<n>'.
        We limit to 10 new tokens to avoid garbage generation, then parse
        only the first meaningful line.
        """
        formatted = LG_PROMPT_TEMPLATE.format(query=prompt)
        inputs = self.tokenizer(formatted, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=10,
                do_sample=False,
                temperature=1.0,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        response = self.tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        ).strip()
        # Take only the first line (LG should output one token)
        first_line = response.split("\n")[0].strip()
        return first_line

    def _parse_lg_response(self, response: str) -> tuple:
        """Parse LG response into (is_safe, category_code, category_name)."""
        response = response.strip().strip('"').strip("'").lower()

        if response == "safe":
            return True, None, None

        # "unsafe" without a specific code — still unsafe
        if response == "unsafe":
            return False, None, "Unsafe (general)"

        # Extract category code (S1-S15)
        code = response.upper().replace(" ", "")
        if code.startswith("S") and code[1:].isdigit():
            num = code[1:]
            if num in LG_CATEGORIES:
                return False, f"S{num}", LG_CATEGORIES[num]

        # Fallback: if response contains a category code somewhere
        for i in range(1, 16):
            code = f"S{i}"
            if code in response.upper():
                return False, code, LG_CATEGORIES[code]

        # If "unsafe" appears anywhere in the response
        if "unsafe" in response:
            return False, None, "Unsafe (general)"

        # If we can't parse, treat as safe but log warning
        print(f"  [WARN] Unparseable LG response: {response!r}")
        return True, None, None

    def _detect_injection_heuristic(self, prompt: str) -> bool:
        """Simple keyword heuristic for prompt injection detection."""
        lower = prompt.lower()
        return any(kw in lower for kw in INJECTION_KEYWORDS)

    def _determine_attack_family(
        self, lg_category_name: str, prompt: str
    ) -> str:
        """Determine specific attack family from LG category + prompt heuristics."""
        # If LG flagged as PII/Privacy
        if lg_category_name and "PII" in lg_category_name:
            return "data_extraction"

        # If LG flagged as Malware/Cybersecurity
        if lg_category_name and "Malware" in lg_category_name:
            return "cybersecurity"

        # If heuristic detects injection patterns
        if self._detect_injection_heuristic(prompt):
            return "prompt_injection"

        # If LG flagged as criminal/weapons/drugs
        if lg_category_name and any(
            k in lg_category_name
            for k in ["Criminal", "Guns", "Regulated", "Substances"]
        ):
            return "criminal_activity"

        # If LG flagged as violence/hate/harmful
        if lg_category_name:
            return "harmful_content"

        return "none"

    # ── Public API ──────────────────────────────────────────────
    def classify(
        self,
        prompt: str,
        prompt_id: str = "",
        user_id: str = "",
        org_id: str = "",
    ) -> dict:
        """Classify a prompt and return DLSM-formatted JSON dict."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

        # Run Llama Guard
        lg_response = self._query_lg(prompt)
        is_safe, lg_code, lg_category = self._parse_lg_response(lg_response)

        # Determine risk score
        # If unsafe: map confidence based on category severity
        if not is_safe:
            # Base risk from category presence
            risk_score = 0.85
            # Boost for injection-specific patterns
            if self._detect_injection_heuristic(prompt):
                risk_score = 0.92
            # Boost for high-severity categories
            if lg_code in ("S4", "S7", "S8", "S11", "S12"):
                risk_score = min(risk_score + 0.05, 0.99)
        else:
            # Safe but check heuristics
            if self._detect_injection_heuristic(prompt):
                risk_score = 0.75  # Heuristic override
                is_safe = False
                lg_category = "Prompt Injection (heuristic)"
            else:
                risk_score = 0.05

        # Map to DLSM taxonomy
        if is_safe:
            dlsm_class = "class_4_compliant_use"
            attack_family = "none"
            binary_label = "safe"
        else:
            dlsm_class, default_family = DLSM_MAP.get(
                lg_category, ("class_1_prompt_subversion", "harmful_content")
            )
            attack_family = self._determine_attack_family(lg_category, prompt)
            if attack_family == "none":
                attack_family = default_family
            binary_label = "attack"

        result = {
            "promptId": prompt_id,
            "userId": user_id,
            "orgId": org_id,
            "promptHash": prompt_hash,
            "riskScore": round(risk_score, 4),
            "binaryLabel": binary_label,
            "dlsmClass": dlsm_class,
            "attackFamily": attack_family,
            "modelVersion": "dlsm-ml-v1",
            "timestamp": int(time.time()),
        }
        return result


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DLSM Stage 2 Filter (Llama Guard 3 1B)")
    parser.add_argument("--prompt", type=str, help="Single prompt to classify")
    parser.add_argument("--prompt-id", type=str, default="req-001", help="Prompt ID")
    parser.add_argument("--user-id", type=str, default="demo-user", help="User ID")
    parser.add_argument("--org-id", type=str, default="Org1", help="Organization ID")
    parser.add_argument("--input-file", type=str, help="File with one prompt per line")
    parser.add_argument("--model-id", type=str, default=MODEL_ID, help="HuggingFace model ID")
    args = parser.parse_args()

    if not args.prompt and not args.input_file:
        parser.error("Provide --prompt or --input-file")

    sf = Stage2Filter(model_id=args.model_id)

    prompts = []
    if args.prompt:
        prompts.append(args.prompt)
    elif args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as f:
            prompts = [line.strip() for line in f if line.strip()]

    print(f"\nClassifying {len(prompts)} prompt(s) ...\n")
    print("=" * 70)

    for i, prompt in enumerate(prompts, 1):
        result = sf.classify(
            prompt,
            prompt_id=f"{args.prompt_id}-{i:03d}",
            user_id=args.user_id,
            org_id=args.org_id,
        )
        print(f"\n--- Prompt {i} ---")
        print(f"  Input : {prompt[:100]}{'...' if len(prompt) > 100 else ''}")
        print(f"  Label : {result['binaryLabel']}")
        print(f"  Risk  : {result['riskScore']}")
        print(f"  Class : {result['dlsmClass']}")
        print(f"  Family: {result['attackFamily']}")
        print(f"\n{json.dumps(result, indent=2)}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
