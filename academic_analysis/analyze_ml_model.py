"""analyze_ml_model.py — ML classifier + dataset academic analysis.

Runs the DLSM classifier against the full TEST_PROMPTS suite (the same 118
prompts used by ml-service/test_pipeline_api.py) through the LIVE ML service
and produces:

  * per-category catch rates
  * confusion matrix / accuracy / precision / recall / F1
  * risk-score distributions for attacks vs. benign prompts
  * multi-turn context-aware classification (crescendo / escalation / benign)
  * a riskScore threshold sweep (detection rate vs false-positive rate)

Writes JSON + figures + a markdown section under academic_analysis/results.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import matplotlib.pyplot as plt

import config as C
import common
from common import Report, save_fig, save_json, style_axis

# Import the shared test-prompt definitions without requiring ml-service deps.
# The file is a plain stdlib script, so it is safe to import.
REPO = C.REPO_ROOT
ML_TEST = REPO / "ml-service" / "test_pipeline_api.py"
if str(ML_TEST.parent) not in sys.path:
    sys.path.insert(0, str(ML_TEST.parent))


def load_test_prompts() -> dict[str, list[str]]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("tp", ML_TEST)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TEST_PROMPTS, mod.MULTI_TURN_SCENARIOS


def classify(url: str, prompt: str, prompt_id: str, history: list[str] | None = None, timeout: int = C.HTTP_TIMEOUT) -> dict[str, Any]:
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    body = {
        "promptId": prompt_id,
        "userId": "acad-model",
        "orgId": "Org1",
        "prompt": prompt,
        "promptHash": prompt_hash,
    }
    if history:
        body["conversationId"] = f"acad-conv-{prompt_id}"
        body["history"] = history
    start = time.perf_counter()
    result = common.http_request("POST", f"{url}/classify", body, timeout=timeout)
    result["_latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
    result["prompt"] = prompt
    return result


def collect(results_dir: Path, ml_url: str) -> dict[str, Any]:
    prompts, mt_scenarios = load_test_prompts()
    rows: list[dict[str, Any]] = []
    mt_rows: list[dict[str, Any]] = []

    for category, prompts_list in prompts.items():
        is_benign = category == "benign"
        for prompt in prompts_list:
            pid = f"acad-model-{category[:6]}-{len(rows):04d}"
            r = classify(ml_url, prompt, pid)
            r["test_category"] = category
            r["expected_benign"] = is_benign
            rows.append(r)
            if len(rows) % 25 == 0:
                print(f"  [{len(rows)}] {category:32s} done")

    for scenario in mt_scenarios:
        seen: list[str] = []
        for i, turn in enumerate(scenario["conversation"]):
            pid = f"acad-mt-{scenario['case_id'][:8]}-{i:02d}"
            r = classify(ml_url, turn, pid, history=list(seen))
            r["test_category"] = f"multi_turn:{scenario['case_id']}"
            r["expected_benign"] = scenario.get("benign", False)
            r["turn_index"] = i
            r["contextAware"] = bool(seen)
            mt_rows.append(r)
            seen.append(turn)

    return {"rows": rows, "multi_turn_rows": mt_rows, "ml_health": common.health(ml_url)}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [r for r in rows if not r["expected_benign"]]
    benign = [r for r in rows if r["expected_benign"]]
    tp = sum(1 for r in attacks if r.get("binaryLabel") == "attack")
    fn = sum(1 for r in attacks if r.get("binaryLabel") != "attack")
    tn = sum(1 for r in benign if r.get("binaryLabel") != "attack")
    fp = sum(1 for r in benign if r.get("binaryLabel") == "attack")

    total = len(rows)
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    # Per-category catch rates
    cat_counts: dict[str, dict[str, Any]] = {}
    for r in rows:
        cat = r.get("test_category", "?")
        d = cat_counts.setdefault(cat, {"total": 0, "caught": 0, "risks": []})
        d["total"] += 1
        if not r["expected_benign"] and r.get("binaryLabel") == "attack":
            d["caught"] += 1
        d["risks"].append(r.get("riskScore", 0))

    fp_list = [r for r in benign if r.get("binaryLabel") == "attack"]
    fn_list = [r for r in attacks if r.get("binaryLabel") != "attack"]

    lat = [r.get("_latency_ms", 0) for r in rows if r.get("_latency_ms") is not None]

    return {
        "total": total,
        "attacks": len(attacks),
        "benign": len(benign),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "benign_pass_rate": round(tn / (tn + fp), 4) if (tn + fp) else 0,
        "attack_catch_rate": round(rec, 4),
        "false_positives": fp,
        "false_negatives": fn,
        "fp_prompts": [r.get("prompt", "")[:120] for r in fp_list],
        "fn_prompts": [r.get("prompt", "")[:120] for r in fn_list],
        "category_rates": {k: round(v["caught"] / v["total"], 4) if v["total"] else 0 for k, v in cat_counts.items()},
        "category_counts": {k: v["total"] for k, v in cat_counts.items()},
        "latency_ms": {"avg": round(float(np.mean(lat)), 1) if lat else 0, "p50": round(float(np.median(lat)), 1) if lat else 0},
    }


def multi_turn_metrics(mt_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_conv: dict[str, list[dict[str, Any]]] = {}
    for r in mt_rows:
        by_conv.setdefault(r["test_category"], []).append(r)

    attack_scenarios = 0
    caught_final = 0
    benign_scenarios = 0
    benign_ok = 0
    for conv, turns in by_conv.items():
        last = max(turns, key=lambda t: t.get("turn_index", 0))
        if last["expected_benign"]:
            benign_scenarios += 1
            if last.get("binaryLabel") != "attack":
                benign_ok += 1
        else:
            attack_scenarios += 1
            if last.get("binaryLabel") == "attack":
                caught_final += 1

    return {
        "attack_scenarios": attack_scenarios,
        "final_turn_catch": round(caught_final / attack_scenarios, 4) if attack_scenarios else 0,
        "caught_final": caught_final,
        "attack_scenario_total": attack_scenarios,
        "benign_scenarios": benign_scenarios,
        "benign_stays_benign": benign_ok == benign_scenarios,
        "benign_stays_benign_ok": benign_ok,
    }


def threshold_sweep(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [r.get("riskScore", 0) for r in rows if not r["expected_benign"]]
    benign = [r.get("riskScore", 0) for r in rows if r["expected_benign"]]
    thresholds = [round(t, 2) for t in np.arange(0.0, 1.01, 0.05)]
    out = []
    for t in thresholds:
        tp = sum(1 for x in attacks if x >= t)
        fp = sum(1 for x in benign if x >= t)
        out.append({
            "threshold": t,
            "detection_rate": round(tp / len(attacks), 4) if attacks else 0,
            "false_positive_rate": round(fp / len(benign), 4) if benign else 0,
        })
    return {"curve": out}


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def fig_confusion(m: dict[str, Any]) -> str:
    cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
    fig, ax = plt.subplots(figsize=(4.4, 3.6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["benign", "attack"])
    ax.set_yticks([0, 1], ["benign", "attack"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black" if cm[i, j] < cm.max() / 1.4 else "white", fontsize=14)
    fig.colorbar(im, fraction=0.046)
    ax.set_title(f"Confusion matrix (accuracy {m['accuracy']:.1%})")
    return save_fig(fig, "fig_confusion_matrix.png")


def fig_catch_rates(cat_rates: dict[str, Any], cat_counts: dict[str, Any]) -> str:
    cats = sorted(cat_rates, key=lambda c: cat_rates[c])
    rates = [cat_rates[c] for c in cats]
    counts = [cat_counts.get(c, 0) for c in cats]
    fig, ax = plt.subplots(figsize=(8, 4.4))
    bars = ax.barh(cats, rates, color="#2a6f97")
    for b, cnt in zip(bars, counts):
        ax.text(b.get_width() + 0.01, b.get_y() + b.get_height() / 2, f"{cnt}", va="center", fontsize=8)
    ax.set_xlim(0, 1.05)
    style_axis(ax, "Attack catch rate by prompt category", ylabel="")
    ax.axvline(1.0, color="gray", lw=0.8, ls="--")
    return save_fig(fig, "fig_catch_rates.png")


def fig_risk_distribution(rows: list[dict[str, Any]]) -> str:
    attacks = [r.get("riskScore", 0) for r in rows if not r["expected_benign"]]
    benign = [r.get("riskScore", 0) for r in rows if r["expected_benign"]]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(attacks, bins=24, alpha=0.65, label=f"attacks (n={len(attacks)})", color="#d1495b")
    ax.hist(benign, bins=24, alpha=0.65, label=f"benign (n={len(benign)})", color="#2a9d8f")
    for t, name in [(C.SINGLE_TURN_BLOCK, "gateway block"), (C.SINGLE_TURN_REVIEW, "gateway review")]:
        ax.axvline(t, color="gray", ls="--", lw=1, alpha=0.8)
        ax.text(t, ax.get_ylim()[1] * 0.95, name, rotation=90, fontsize=7, va="top")
    ax.legend(fontsize=9)
    style_axis(ax, "Classifier risk-score distribution", "risk score (P(malicious))", "count")
    return save_fig(fig, "fig_risk_distribution.png")


def fig_threshold_sweep(curve: list[dict[str, Any]]) -> str:
    fig, ax = plt.subplots(figsize=(6.4, 4))
    th = [c["threshold"] for c in curve]
    det = [c["detection_rate"] for c in curve]
    fpr = [c["false_positive_rate"] for c in curve]
    ax.plot(th, det, marker="o", ms=3, label="detection rate (attacks)", color="#1d3557")
    ax.plot(th, fpr, marker="s", ms=3, label="false-positive rate (benign)", color="#e63946")
    ax.axvline(C.SINGLE_TURN_BLOCK, color="gray", ls="--", lw=1)
    ax.axvline(C.SINGLE_TURN_REVIEW, color="gray", ls=":", lw=1)
    ax.legend(fontsize=8)
    style_axis(ax, "Risk-threshold sweep (gateway operating points)", "risk threshold", "rate")
    return save_fig(fig, "fig_threshold_sweep.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ml_url = C.ML_URL.rstrip("/")
    print(f"ML model analysis against {ml_url}")

    if not common.health(ml_url).get("status") == "ok":
        print("ML service not reachable; cannot run model analysis.")
        return 1

    C.mk_results()
    prompts, _ = load_test_prompts()
    print(f"Loaded {sum(len(v) for v in prompts.values())} prompts from TEST_PROMPTS")

    data = collect(C.RESULTS_DIR, ml_url)
    metrics = compute_metrics(data["rows"])
    mt = multi_turn_metrics(data["multi_turn_rows"])
    sweep = threshold_sweep(data["rows"])

    payload = {"metrics": metrics, "multi_turn": mt, "threshold_sweep": sweep}
    save_json(payload, "ml_model_analysis.json")
    save_json({"rows": data["rows"], "multi_turn_rows": data["multi_turn_rows"]}, "ml_model_raw.json")

    fn1 = fig_confusion(metrics)
    fn2 = fig_catch_rates(metrics["category_rates"], metrics["category_counts"])
    fn3 = fig_risk_distribution(data["rows"])
    fn4 = fig_threshold_sweep(sweep["curve"])

    rep = Report("report_01_ml_model.md", "ML Classifier & Dataset Analysis")
    rep.p(f"ML service: `{ml_url}` — version `{data['ml_health'].get('version')}`, stage1_loaded={data['ml_health'].get('stage1_loaded')}, stage2_loaded={data['ml_health'].get('stage2_loaded')}")
    rep.h1("Overall metrics")
    rep.table(
        ["metric", "value"],
        [
            ["prompts", metrics["total"]],
            ["attacks / benign", f"{metrics['attacks']} / {metrics['benign']}"],
            ["accuracy", f"{metrics['accuracy']:.1%}"],
            ["precision", f"{metrics['precision']:.1%}"],
            ["recall (attack catch)", f"{metrics['recall']:.1%}"],
            ["F1", f"{metrics['f1']:.3f}"],
            ["benign pass rate", f"{metrics['benign_pass_rate']:.1%}"],
            ["false positives", metrics["false_positives"]],
            ["false negatives", metrics["false_negatives"]],
            ["avg latency", f"{metrics['latency_ms']['avg']} ms"],
        ],
    )
    rep.figure(fn1, "Classifier confusion matrix on the 118-prompt suite.")
    rep.figure(fn2, "Attack catch rate by prompt category (n = count in suite).")
    rep.figure(fn3, "Risk-score distributions for attacks vs benign prompts with gateway operating points.")
    rep.figure(fn4, "Risk-threshold sweep: detection vs false-positive trade-off.")

    rep.h1("Multi-turn context-aware classification")
    rep.table(
        ["metric", "value"],
        [
            ["attack scenarios", mt["attack_scenarios"]],
            ["final-turn catch rate", f"{mt['final_turn_catch']:.1%} ({mt['caught_final']}/{mt['attack_scenario_total']})"],
            ["benign scenarios", mt["benign_scenarios"]],
            ["benign stays benign", mt["benign_stays_benign"]],
        ],
    )

    rep.h1("False positives / negatives")
    rep.h2("False positives (benign flagged as attack)")
    for p in metrics["fp_prompts"]:
        rep.p(f"- {p}")
    rep.h2("False negatives (attacks passed)")
    for p in metrics["fn_prompts"]:
        rep.p(f"- {p}")

    rep.write()
    print("Wrote report_01_ml_model.md + figures")
    print(json.dumps({k: metrics[k] for k in ("accuracy", "precision", "recall", "f1", "false_positives", "false_negatives")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
