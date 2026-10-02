#!/usr/bin/env python3
"""
THE single, one-time read of the locked test set (R2) for this comparison.

Scores all four models — the current-split RF/IF retrains from
train_rf_if_current_split.py (same hyperparameters as production rf_v11/
if_v10, retrained on the exact same split MLP/AE use — see that script's
docstring for why committed rf.onnx/if.onnx are not used directly here) and
the MLP/Autoencoder baselines — against training/splits/test.parquet in one
pass. This is also the first test-set confirmation ever recorded for a
rf_v11/if_v10-equivalent model (the last one on file,
training/results/v10_test_results.json, is for the prior rf_v10/if_v9
pair) — so this script satisfies task A34's comparison AND gives this
model generation its own test-set confirmation, in a single read covering
all four models, per the instruction not to spend a second, separate read
on RF/IF alone.

Do not re-run this script casually. Re-running it against the same
test.parquet is itself a second read of the locked partition and should be
treated with the same care as any other R2 violation.

Usage:
    python3 training/baselines/evaluate_test_once.py
"""
import json

import numpy as np
import onnxruntime as ort
from sklearn.metrics import f1_score, classification_report

from common import load_split, rf_xy, if_xy, TARGET_NAMES, ATTACK_CLASSES, MODELS_OUT, RESULTS_OUT

RF_ONNX = MODELS_OUT / "rf_current_split.onnx"
IF_ONNX = MODELS_OUT / "if_current_split.onnx"
MLP_ONNX = MODELS_OUT / "mlp.onnx"
AE_ONNX = MODELS_OUT / "autoencoder.onnx"

RF_CLASSES = ["benign", "cmdi", "path_traversal", "sqli", "xss"]

# This generation's own val-selected operating point (train_rf_if_current_split.py),
# not the older committed parity_report.json value — that was calibrated on
# the older data snapshot, see train_rf_if_current_split.py's docstring.
IF_THRESHOLD = json.loads(
    (RESULTS_OUT / "rf_if_current_split_metadata.json").read_text()
)["if"]["threshold"]


def onnx_predict_proba(onnx_path, X: np.ndarray) -> np.ndarray:
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    out = sess.run(None, {input_name: X.astype(np.float32)})
    return out[1]  # output index 1 = probabilities (parity_report.json convention)


def onnx_predict_score(onnx_path, X: np.ndarray) -> np.ndarray:
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    out = sess.run(None, {input_name: X.astype(np.float32)})
    return out[1].reshape(-1)  # output index 1 = decision_function score


def score_classifier(name: str, onnx_path, X: np.ndarray, y_true) -> dict:
    proba = onnx_predict_proba(onnx_path, X)
    y_pred = np.array(RF_CLASSES)[proba.argmax(axis=1)]
    print(f"=== {name} — Test Set (R2 one-time read) ===")
    print(classification_report(y_true, y_pred, target_names=TARGET_NAMES))
    macro_f1 = f1_score(y_true, y_pred, average="macro")
    per_class = f1_score(y_true, y_pred, average=None, labels=ATTACK_CLASSES)
    return {
        "macro_f1_test": float(macro_f1),
        "per_class_f1_test": {c: float(f) for c, f in zip(ATTACK_CLASSES, per_class)},
    }


def score_if(X: np.ndarray, y_true) -> dict:
    scores = onnx_predict_score(IF_ONNX, X)
    y_binary = (y_true != "benign").astype(int).to_numpy()
    predicted_attack = (scores < IF_THRESHOLD).astype(int)
    tp = ((predicted_attack == 1) & (y_binary == 1)).sum()
    fp = ((predicted_attack == 1) & (y_binary == 0)).sum()
    fn = ((predicted_attack == 0) & (y_binary == 1)).sum()
    tn = ((predicted_attack == 0) & (y_binary == 0)).sum()
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"=== IF (if_v10) — Test Set (R2 one-time read) ===")
    print(f"Recall: {recall:.4f}  FP rate: {fp_rate:.4f}  (threshold={IF_THRESHOLD})")
    return {"recall_test": float(recall), "fp_rate_test": float(fp_rate), "threshold": IF_THRESHOLD}


def score_autoencoder(X: np.ndarray, y_true) -> dict:
    scaler = json.loads((MODELS_OUT / "autoencoder_scaler.json").read_text())
    mean = np.array(scaler["mean"], dtype=np.float32)
    scale = np.array(scaler["scale"], dtype=np.float32)
    X_scaled = ((X - mean) / scale).astype(np.float32)

    sess = ort.InferenceSession(str(AE_ONNX), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    # skl2onnx exports MLPRegressor's multi-output as a flat (N * n_outputs, 1)
    # column, not (N, n_outputs) — reshape back before comparing to X_scaled.
    X_hat = sess.run(None, {input_name: X_scaled})[0].reshape(X_scaled.shape)
    scores = np.mean((X_scaled - X_hat) ** 2, axis=1)

    ae_meta = json.loads((RESULTS_OUT / "autoencoder_metadata.json").read_text())
    threshold = ae_meta["selected_threshold"]

    y_binary = (y_true != "benign").astype(int).to_numpy()
    predicted_attack = (scores > threshold).astype(int)
    tp = ((predicted_attack == 1) & (y_binary == 1)).sum()
    fp = ((predicted_attack == 1) & (y_binary == 0)).sum()
    fn = ((predicted_attack == 0) & (y_binary == 1)).sum()
    tn = ((predicted_attack == 0) & (y_binary == 0)).sum()
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"=== Autoencoder — Test Set (R2 one-time read) ===")
    print(f"Recall: {recall:.4f}  FP rate: {fp_rate:.4f}  (threshold={threshold})")
    return {"recall_test": float(recall), "fp_rate_test": float(fp_rate), "threshold": threshold}


def main():
    test_df = load_split("test")
    print(f"Test set: {test_df.shape} — reading ONCE, do not re-run this script.")

    X_test_rf, y_test_rf = rf_xy(test_df)
    X_test_if, y_test_if = if_xy(test_df)

    results = {
        "rf_v11": score_classifier("RF (rf_v11)", RF_ONNX, X_test_rf.to_numpy(), y_test_rf),
        "mlp": score_classifier("MLP baseline", MLP_ONNX, X_test_rf.to_numpy(), y_test_rf),
        "if_v10": score_if(X_test_if.to_numpy(), y_test_if),
        "autoencoder": score_autoencoder(X_test_if.to_numpy(), y_test_if),
    }

    out_path = RESULTS_OUT / "test_set_comparison.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nSaved (single R2 read, do not repeat): {out_path}")


if __name__ == "__main__":
    main()
