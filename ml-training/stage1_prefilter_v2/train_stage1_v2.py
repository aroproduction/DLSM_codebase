"""
train_stage1_v2.py
------------------
Extended-schedule retraining of the DLSM Stage 1 fast prefilter, instrumented to
export the artifacts needed for the paper's training-performance figures:

  * per-epoch training loss / validation loss   -> loss-epoch curve
  * per-epoch validation accuracy / F1          -> convergence curve
  * test-set ROC curve + AUC                    -> ROC-AUC figure
  * test-set precision-recall curve + AP        -> PR figure
  * operating-point table at the deployed pipeline thresholds (0.60 / 0.95)

Model : distilbert-base-uncased (binary head)
Data  : ../datasets/combined_stage1_dataset_split  (fixed stratified splits, seed 42)
Output: ./stage1_prefilter_v2  +  ./training_artifacts/training_history.json

Usage:
    python train_stage1_v2.py
"""

import os
import json
import numpy as np
from datasets import load_from_disk
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
    roc_auc_score,
    precision_recall_curve,
    average_precision_score,
    classification_report,
    confusion_matrix,
)
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
import torch

# ─────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────
MODEL_NAME    = "distilbert-base-uncased"
SPLIT_PATH    = "../datasets/combined_stage1_dataset_split"
OUTPUT_DIR    = "./stage1_prefilter_v2"
ARTIFACT_DIR  = "./training_artifacts"

MAX_LENGTH    = 384
TRAIN_BATCH   = 32
EVAL_BATCH    = 64
NUM_EPOCHS    = 15       # extended from 5 -> full convergence/overfit curve
LEARNING_RATE = 1e-5
WEIGHT_DECAY  = 0.05
WARMUP_RATIO  = 0.15
GRAD_ACCUM    = 2
SEED          = 42

# Pipeline decision thresholds documented in the paper (Sec. Classifier Service)
PIPELINE_THRESHOLDS = [0.60, 0.95]

os.makedirs(ARTIFACT_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────
# 1. LOAD FIXED SPLITS
# ─────────────────────────────────────────────────────────────────
print("=" * 64)
print("Loading combined dataset splits")
print("=" * 64)

raw_ds = load_from_disk(SPLIT_PATH)
for name in ("train", "validation", "test"):
    labels = raw_ds[name]["label"]
    n_mal = sum(1 for x in labels if x == 1)
    print(f"  {name:11s} total={len(labels):6,}  malicious={n_mal:6,}  benign={len(labels)-n_mal:6,}")

# ─────────────────────────────────────────────────────────────────
# 2. TOKENISE
# ─────────────────────────────────────────────────────────────────
print("\nTokenising ...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


def tokenize_fn(batch):
    return tokenizer(batch["text"], truncation=True, padding=False, max_length=MAX_LENGTH)


tok_ds = raw_ds.map(tokenize_fn, batched=True, remove_columns=["text"], desc="Tokenising")
tok_ds = tok_ds.rename_column("label", "labels")
tok_ds.set_format("torch")

# ─────────────────────────────────────────────────────────────────
# 3. MODEL
# ─────────────────────────────────────────────────────────────────
print(f"\nLoading {MODEL_NAME!r} ...")
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=2,
    id2label={0: "benign", 1: "malicious"},
    label2id={"benign": 0, "malicious": 1},
)
print(f"  Parameters: {sum(p.numel() for p in model.parameters()) / 1e6:.1f}M")


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy":  accuracy_score(labels, preds),
        "f1":        f1_score(labels, preds, pos_label=1, zero_division=0),
        "precision": precision_score(labels, preds, pos_label=1, zero_division=0),
        "recall":    recall_score(labels, preds, pos_label=1, zero_division=0),
    }


# ─────────────────────────────────────────────────────────────────
# 4. TRAINING ARGS
# ─────────────────────────────────────────────────────────────────
use_fp16 = torch.cuda.is_available()
print(f"\nCUDA: {torch.cuda.is_available()}")
if use_fp16:
    print(f"  GPU : {torch.cuda.get_device_name(0)}")

steps_per_epoch = len(tok_ds["train"]) // (TRAIN_BATCH * GRAD_ACCUM)
total_steps = steps_per_epoch * NUM_EPOCHS
warmup_steps = int(total_steps * WARMUP_RATIO)
print(f"  Steps/epoch={steps_per_epoch}  total={total_steps}  warmup={warmup_steps}")

training_args = TrainingArguments(
    output_dir                  = OUTPUT_DIR,
    num_train_epochs            = NUM_EPOCHS,
    per_device_train_batch_size = TRAIN_BATCH,
    per_device_eval_batch_size  = EVAL_BATCH,
    learning_rate               = LEARNING_RATE,
    weight_decay                = WEIGHT_DECAY,
    warmup_steps                = warmup_steps,
    gradient_accumulation_steps = GRAD_ACCUM,
    eval_strategy               = "epoch",
    save_strategy               = "epoch",
    logging_strategy            = "epoch",   # one clean train-loss point per epoch
    save_total_limit            = 2,         # keep best + last only (268 MB each)
    load_best_model_at_end      = True,
    metric_for_best_model       = "f1",
    greater_is_better           = True,
    fp16                        = use_fp16,
    seed                        = SEED,
    report_to                   = "none",
)

trainer = Trainer(
    model           = model,
    args            = training_args,
    train_dataset   = tok_ds["train"],
    eval_dataset    = tok_ds["validation"],
    data_collator   = DataCollatorWithPadding(tokenizer=tokenizer),
    compute_metrics = compute_metrics,
)

# ─────────────────────────────────────────────────────────────────
# 5. TRAIN (full schedule, no early stop -> complete loss curve)
# ─────────────────────────────────────────────────────────────────
print("\n" + "=" * 64)
print(f"Training for {NUM_EPOCHS} epochs")
print("=" * 64)

train_result = trainer.train()
print(f"\nRuntime: {train_result.metrics['train_runtime']:.1f}s "
      f"({train_result.metrics['train_samples_per_second']:.1f} samples/s)")

# ─────────────────────────────────────────────────────────────────
# 6. EXTRACT PER-EPOCH HISTORY
# ─────────────────────────────────────────────────────────────────
per_epoch = {}
for rec in trainer.state.log_history:
    ep = rec.get("epoch")
    if ep is None:
        continue
    key = round(float(ep), 4)
    slot = per_epoch.setdefault(key, {})
    if "loss" in rec:
        slot["train_loss"] = rec["loss"]
    if "eval_loss" in rec:
        slot["val_loss"]      = rec["eval_loss"]
        slot["val_accuracy"]  = rec.get("eval_accuracy")
        slot["val_f1"]        = rec.get("eval_f1")
        slot["val_precision"] = rec.get("eval_precision")
        slot["val_recall"]    = rec.get("eval_recall")

epochs_sorted = sorted(k for k, v in per_epoch.items() if "train_loss" in v or "val_loss" in v)
history = {
    "epoch":         [],
    "train_loss":    [],
    "val_loss":      [],
    "val_accuracy":  [],
    "val_f1":        [],
    "val_precision": [],
    "val_recall":    [],
}
for ep in epochs_sorted:
    slot = per_epoch[ep]
    if "train_loss" not in slot or "val_loss" not in slot:
        continue
    history["epoch"].append(ep)
    history["train_loss"].append(slot["train_loss"])
    history["val_loss"].append(slot["val_loss"])
    history["val_accuracy"].append(slot["val_accuracy"])
    history["val_f1"].append(slot["val_f1"])
    history["val_precision"].append(slot["val_precision"])
    history["val_recall"].append(slot["val_recall"])

print("\n" + "-" * 64)
print(f"{'Epoch':>5}  {'TrainLoss':>10}  {'ValLoss':>9}  {'ValAcc':>7}  {'ValF1':>7}")
print("-" * 64)
for i, ep in enumerate(history["epoch"]):
    print(f"{ep:5.0f}  {history['train_loss'][i]:10.4f}  {history['val_loss'][i]:9.4f}  "
          f"{history['val_accuracy'][i]:7.4f}  {history['val_f1'][i]:7.4f}")

best_ep_idx = int(np.argmax(history["val_f1"]))
min_vloss_idx = int(np.argmin(history["val_loss"]))
print("-" * 64)
print(f"  Best val F1   : epoch {history['epoch'][best_ep_idx]:.0f} "
      f"(F1={history['val_f1'][best_ep_idx]:.4f})")
print(f"  Min val loss  : epoch {history['epoch'][min_vloss_idx]:.0f} "
      f"(loss={history['val_loss'][min_vloss_idx]:.4f})")

# ─────────────────────────────────────────────────────────────────
# 7. TEST-SET EVALUATION + ROC / PR CURVES
# ─────────────────────────────────────────────────────────────────
print("\n" + "=" * 64)
print("Test-set evaluation (best checkpoint)")
print("=" * 64)

pred_out = trainer.predict(tok_ds["test"])
logits = pred_out.predictions
y_true = np.array(raw_ds["test"]["label"])

# softmax -> P(malicious) == the pipeline's risk score
exp = np.exp(logits - logits.max(axis=1, keepdims=True))
probs = exp / exp.sum(axis=1, keepdims=True)
y_score = probs[:, 1]
y_pred = (y_score >= 0.5).astype(int)

test_metrics = {
    "accuracy":  float(accuracy_score(y_true, y_pred)),
    "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
    "recall":    float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
    "f1":        float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
    "loss":      float(pred_out.metrics.get("test_loss", float("nan"))),
}
roc_auc = float(roc_auc_score(y_true, y_score))
ap = float(average_precision_score(y_true, y_score))

print(f"  Accuracy  : {test_metrics['accuracy']:.4f}")
print(f"  Precision : {test_metrics['precision']:.4f}")
print(f"  Recall    : {test_metrics['recall']:.4f}")
print(f"  F1        : {test_metrics['f1']:.4f}")
print(f"  ROC-AUC   : {roc_auc:.4f}")
print(f"  PR-AUC(AP): {ap:.4f}")

print("\n" + classification_report(y_true, y_pred, target_names=["benign", "malicious"], digits=4))
cm = confusion_matrix(y_true, y_pred)
print("Confusion matrix (rows=true, cols=pred):")
print(f"  true_benign    -> benign={cm[0,0]:5d}  malicious={cm[0,1]:5d}")
print(f"  true_malicious -> benign={cm[1,0]:5d}  malicious={cm[1,1]:5d}")

fpr, tpr, roc_thr = roc_curve(y_true, y_score)
prec_c, rec_c, pr_thr = precision_recall_curve(y_true, y_score)

# Youden's J optimal point
j_scores = tpr - fpr
j_idx = int(np.argmax(j_scores))
print(f"\n  Youden-optimal threshold = {roc_thr[j_idx]:.4f} "
      f"(TPR={tpr[j_idx]:.4f}, FPR={fpr[j_idx]:.4f})")

# Operating points at the deployed pipeline thresholds
print("\n  Operating points at deployed pipeline thresholds:")
operating_points = []
for thr in PIPELINE_THRESHOLDS:
    yp = (y_score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, yp, labels=[0, 1]).ravel()
    op = {
        "threshold": thr,
        "tpr":       float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "fpr":       float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
        "recall":    float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "f1":        float(f1_score(y_true, yp, pos_label=1, zero_division=0)),
        "accuracy":  float(accuracy_score(y_true, yp)),
    }
    operating_points.append(op)
    print(f"    x >= {thr:.2f}  TPR={op['tpr']:.4f}  FPR={op['fpr']:.4f}  "
          f"P={op['precision']:.4f}  F1={op['f1']:.4f}")

# ─────────────────────────────────────────────────────────────────
# 8. SAVE MODEL + ARTIFACTS
# ─────────────────────────────────────────────────────────────────
print("\n" + "=" * 64)
print(f"Saving model -> {OUTPUT_DIR!r}")
print("=" * 64)
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

summary = {
    "model_name":          MODEL_NAME,
    "dataset":             "combined",
    "dataset_source":      "prompt-injections-benchmark + singleturn_jailbreak_dataset (malicious only)",
    "n_train":             len(raw_ds["train"]),
    "n_validation":        len(raw_ds["validation"]),
    "n_test":              len(raw_ds["test"]),
    "max_length":          MAX_LENGTH,
    "num_epochs_trained":  NUM_EPOCHS,
    "best_epoch_val_f1":   history["epoch"][best_ep_idx],
    "min_val_loss_epoch":  history["epoch"][min_vloss_idx],
    "learning_rate":       LEARNING_RATE,
    "weight_decay":        WEIGHT_DECAY,
    "warmup_ratio":        WARMUP_RATIO,
    "gradient_accum":      GRAD_ACCUM,
    "train_batch":         TRAIN_BATCH,
    "test_accuracy":       round(test_metrics["accuracy"], 4),
    "test_precision":      round(test_metrics["precision"], 4),
    "test_recall":         round(test_metrics["recall"], 4),
    "test_f1":             round(test_metrics["f1"], 4),
    "test_roc_auc":        round(roc_auc, 4),
    "test_pr_auc":         round(ap, 4),
    "id2label":            {0: "benign", 1: "malicious"},
}
with open(os.path.join(OUTPUT_DIR, "training_summary.json"), "w") as f:
    json.dump(summary, f, indent=2)

artifacts = {
    "config": {
        "model_name": MODEL_NAME,
        "num_epochs": NUM_EPOCHS,
        "learning_rate": LEARNING_RATE,
        "weight_decay": WEIGHT_DECAY,
        "warmup_ratio": WARMUP_RATIO,
        "max_length": MAX_LENGTH,
        "train_batch": TRAIN_BATCH,
        "grad_accum": GRAD_ACCUM,
        "effective_batch": TRAIN_BATCH * GRAD_ACCUM,
        "seed": SEED,
        "n_train": len(raw_ds["train"]),
        "n_validation": len(raw_ds["validation"]),
        "n_test": len(raw_ds["test"]),
    },
    "history": history,
    "best_epoch_val_f1": history["epoch"][best_ep_idx],
    "min_val_loss_epoch": history["epoch"][min_vloss_idx],
    "test_metrics": test_metrics,
    "roc": {
        "auc": roc_auc,
        "fpr": fpr.tolist(),
        "tpr": tpr.tolist(),
        "thresholds": [float(t) for t in roc_thr],
        "youden_threshold": float(roc_thr[j_idx]),
        "youden_tpr": float(tpr[j_idx]),
        "youden_fpr": float(fpr[j_idx]),
    },
    "pr": {
        "average_precision": ap,
        "precision": prec_c.tolist(),
        "recall": rec_c.tolist(),
    },
    "confusion_matrix_at_0.5": cm.tolist(),
    "operating_points": operating_points,
}
hist_path = os.path.join(ARTIFACT_DIR, "training_history.json")
with open(hist_path, "w") as f:
    json.dump(artifacts, f, indent=2)

print(f"[OK] Model saved to {OUTPUT_DIR}")
print(f"[OK] Curve artifacts saved to {hist_path}")
print("=" * 64)
