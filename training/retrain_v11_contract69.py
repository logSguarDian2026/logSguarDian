"""One-off R2-remediation retrain of rf_v11/if_v10 against the freshly
re-locked split (post-f15e7cc extractor fixes), matching the CURRENT
production feature contract (69 RF / 63 IF, per parity_report.json) --
i.e. non_json_quote_count is excluded, same treatment worker.ts already
gives it, since promoting that new dimension is a separate decision this
retrain does not make.

Replicates notebooks 03/04/05 exactly (same hyperparameters, same
selection procedures), with one added exclusion.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, f1_score

REPO = Path("/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian")
SPLITS = REPO / "training" / "splits"
MODELS = REPO / "training" / "models"
RESULTS = REPO / "training" / "results"

META_COLS = [
    "sample_id", "timestamp", "_source", "_row_hash",
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
]
NOT_YET_PROMOTED = ["non_json_quote_count"]  # matches worker.ts's temporary exclusion
IF_ADDITIONAL_EXCLUDED = [
    "dotdot_encoded_count", "authorization_length", "unusual_headers_count",
    "null_byte_count", "os_path_indicator", "sensitive_file_target",
]

train_df = pd.read_parquet(SPLITS / "train.parquet")
val_df = pd.read_parquet(SPLITS / "val.parquet")

# ---------------- RF (69 features) ----------------
rf_drop = [c for c in META_COLS + NOT_YET_PROMOTED if c in train_df.columns]
X_train_rf = train_df.drop(columns=rf_drop)
X_val_rf = val_df.drop(columns=rf_drop)
y_train = X_train_rf.pop("label")
y_val = X_val_rf.pop("label")
print(f"RF feature count: {X_train_rf.shape[1]}")
assert X_train_rf.shape[1] == 69, X_train_rf.shape[1]

TARGET_NAMES = ["benign", "cmdi", "path_traversal", "sqli", "xss"]

best_rf = RandomForestClassifier(
    n_estimators=30, max_depth=25, class_weight="balanced_subsample",
    random_state=42, n_jobs=-1,
)
best_rf.fit(X_train_rf, y_train)
y_pred_rf = best_rf.predict(X_val_rf)
print(classification_report(y_val, y_pred_rf, target_names=TARGET_NAMES))
macro_f1 = f1_score(y_val, y_pred_rf, average="macro")
per_class = f1_score(y_val, y_pred_rf, average=None, labels=["cmdi", "path_traversal", "sqli", "xss"])
print(f"Macro F1: {macro_f1:.4f}")
assert sum(f >= 0.80 for f in per_class) >= 3, "GATE FAILED: F1 >= 0.80 in fewer than 3 attack classes."

joblib.dump(best_rf, MODELS / "rf_v11.pkl")
rf_metadata = {
    "n_features": X_train_rf.shape[1],
    "eval_set": "val",
    "macro_f1": float(macro_f1),
    "per_class_f1": {c: float(f) for c, f in zip(["cmdi", "path_traversal", "sqli", "xss"], per_class)},
    "classes_meeting_gate": int(sum(f >= 0.80 for f in per_class)),
}
with open(MODELS / "rf_v11_metadata.json", "w") as f:
    json.dump(rf_metadata, f, indent=2)
print("Saved rf_v11.pkl / rf_v11_metadata.json")

# ---------------- IF (63 features) ----------------
if_drop = [c for c in META_COLS + NOT_YET_PROMOTED + IF_ADDITIONAL_EXCLUDED if c in train_df.columns]
X_train_if = train_df.drop(columns=if_drop)
X_val_if = val_df.drop(columns=if_drop)
y_train_if = X_train_if.pop("label")
y_val_if = X_val_if.pop("label")
print(f"IF feature count: {X_train_if.shape[1]}")
assert X_train_if.shape[1] == 63, X_train_if.shape[1]

X_benign = X_train_if[y_train_if == "benign"].copy()
print(f"Benign-only training samples: {X_benign.shape[0]:,}")

CONTAMINATION = 0.05
iso = IsolationForest(
    n_estimators=200, contamination=CONTAMINATION, max_samples=4096,
    random_state=42, n_jobs=-1,
)
iso.fit(X_benign)

scores = iso.decision_function(X_val_if)
y_binary = (y_val_if != "benign").astype(int)

thresholds = np.linspace(scores.min(), scores.max(), 300)
recalls, fp_rates = [], []
for t in thresholds:
    predicted_attack = (scores < t).astype(int)
    tp = ((predicted_attack == 1) & (y_binary == 1)).sum()
    fp = ((predicted_attack == 1) & (y_binary == 0)).sum()
    fn = ((predicted_attack == 0) & (y_binary == 1)).sum()
    tn = ((predicted_attack == 0) & (y_binary == 0)).sum()
    recalls.append(tp / (tp + fn) if (tp + fn) > 0 else 0)
    fp_rates.append(fp / (fp + tn) if (fp + tn) > 0 else 0)

valid = [(t, r, f) for t, r, f in zip(thresholds, recalls, fp_rates) if r >= 0.50 and f <= 0.06]
assert valid, "WARNING: No threshold satisfies recall>=0.50 AND FP<=0.06"
best = max(valid, key=lambda x: x[1])
BEST_THRESHOLD, BEST_RECALL, BEST_FP = best
print(f"Selected threshold: {BEST_THRESHOLD:.4f}  Recall: {BEST_RECALL:.4f}  FP: {BEST_FP:.4f}")

joblib.dump(iso, MODELS / "if_v10.pkl")
if_metadata = {
    "threshold": float(BEST_THRESHOLD),
    "contamination": CONTAMINATION,
    "trained_on": "benign_only",
    "val_recall": float(BEST_RECALL),
    "val_fp_rate": float(BEST_FP),
}
with open(MODELS / "if_v10_metadata.json", "w") as f:
    json.dump(if_metadata, f, indent=2)
print("Saved if_v10.pkl / if_v10_metadata.json")

# ---------------- ONNX export + parity (69/63) ----------------
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as ort

N_FEATURES = X_val_rf.shape[1]
IF_N_FEATURES = X_val_if.shape[1]
TARGET_OPSET = 17

rf_onnx = convert_sklearn(
    best_rf, initial_types=[("float_input", FloatTensorType([None, N_FEATURES]))],
    target_opset=TARGET_OPSET, options={id(best_rf): {"zipmap": False}},
)
with open(MODELS / "rf.onnx", "wb") as f:
    f.write(rf_onnx.SerializeToString())

iso_onnx = convert_sklearn(
    iso, initial_types=[("float_input", FloatTensorType([None, IF_N_FEATURES]))],
    target_opset={"": TARGET_OPSET, "ai.onnx.ml": 3},
)
with open(MODELS / "if.onnx", "wb") as f:
    f.write(iso_onnx.SerializeToString())

# parity check
sample = X_val_rf.sample(n=1000, random_state=42)
sess = ort.InferenceSession(str(MODELS / "rf.onnx"))
onnx_proba = sess.run(None, {"float_input": sample.to_numpy(dtype=np.float32)})[1]
sk_proba = best_rf.predict_proba(sample)
rf_max_diff = float(np.max(np.abs(onnx_proba - sk_proba)))

sample_if = X_val_if.loc[sample.index]
sess_if = ort.InferenceSession(str(MODELS / "if.onnx"))
onnx_score = sess_if.run(None, {"float_input": sample_if.to_numpy(dtype=np.float32)})[1].reshape(-1)
sk_score = iso.decision_function(sample_if)
if_max_diff = float(np.max(np.abs(onnx_score - sk_score)))

print(f"RF max prob diff: {rf_max_diff}")
print(f"IF max score diff: {if_max_diff}")

report = {
    "rf_onnx_path": str(MODELS / "rf.onnx"),
    "if_onnx_path": str(MODELS / "if.onnx"),
    "target_opset": TARGET_OPSET,
    "rf_n_features": N_FEATURES,
    "if_n_features": IF_N_FEATURES,
    "parity_samples": 1000,
    "rf_max_prob_diff": rf_max_diff,
    "if_max_score_diff": if_max_diff,
    "parity_passed": bool(rf_max_diff < 0.001 and if_max_diff < 0.001),
    "threshold_if": BEST_THRESHOLD,
    "if_onnx_output_index": 1,
    "rf_onnx_output_index": 1,
    "rf_classes": list(best_rf.classes_),
    "rf_model_version": "rf_v11",
    "if_model_version": "if_v10",
}
with open(MODELS / "parity_report.json", "w") as f:
    json.dump(report, f, indent=2)
print(json.dumps(report, indent=2))
