#!/usr/bin/env python3
"""
Retrains RF and IF with their exact production hyperparameters (notebooks
03/04) on the CURRENT train/val split — the same one train_mlp.py and
train_autoencoder.py use.

Why this exists instead of reusing committed rf.onnx/if.onnx directly: a
sanity check scoring production rf.onnx against the current val.parquet
gave macro F1 0.9899, not the committed 0.9810 — the committed ONNX models
were trained on an older data snapshot (commit 734c24f, 2026-08-30);
training/data_clean has picked up more curated telemetry and corpus
additions since. Task A34 asks for the comparison to use the EXACT same
split for all four models — scoring a stale RF/IF against a newer val/test
set would not be that. Retraining here (already confirmed reproducible in
Step 1 — RF matches the committed metadata bit-for-bit when run on the data
snapshot that produced it) gives a genuine apples-to-apples RF_v11-equivalent
/ if_v10-equivalent pair on the same partitioning as MLP/AE.

Usage:
    python3 training/baselines/train_rf_if_current_split.py
"""
import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import f1_score, classification_report
from skl2onnx import to_onnx

from common import load_split, rf_xy, if_xy, TARGET_NAMES, ATTACK_CLASSES, MODELS_OUT, RESULTS_OUT

RF_PARAMS = dict(n_estimators=30, max_depth=25, class_weight="balanced_subsample", random_state=42, n_jobs=-1)
IF_PARAMS = dict(n_estimators=200, contamination=0.05, max_samples=4096, random_state=42, n_jobs=-1)
IF_FP_CEILING = 0.06
N_THRESHOLDS = 300


def main():
    train_df = load_split("train")
    val_df = load_split("val")

    # --- RF ---
    X_train, y_train = rf_xy(train_df)
    X_val, y_val = rf_xy(val_df)

    rf = RandomForestClassifier(**RF_PARAMS)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_val)
    print("=== RF (current-split retrain) — Validation Set ===")
    print(classification_report(y_val, y_pred, target_names=TARGET_NAMES))
    rf_macro_f1 = f1_score(y_val, y_pred, average="macro")
    rf_per_class = f1_score(y_val, y_pred, average=None, labels=ATTACK_CLASSES)
    print(f"Macro F1: {rf_macro_f1:.4f}")

    rf_onnx_path = MODELS_OUT / "rf_current_split.onnx"
    rf_onnx = to_onnx(rf, X_train.to_numpy().astype(np.float32), target_opset=17,
                       options={id(rf): {"zipmap": False}})
    rf_onnx_path.write_bytes(rf_onnx.SerializeToString())
    print(f"ONNX exported: {rf_onnx_path} ({rf_onnx_path.stat().st_size / 1024:.1f} KB)")

    # --- IF ---
    X_train_if, y_train_if = if_xy(train_df)
    X_val_if, y_val_if = if_xy(val_df)
    X_benign = X_train_if[y_train_if == "benign"]

    iso = IsolationForest(**IF_PARAMS)
    iso.fit(X_benign)
    scores = iso.decision_function(X_val_if)
    y_binary = (y_val_if != "benign").astype(int).to_numpy()

    thresholds = np.linspace(scores.min(), scores.max(), N_THRESHOLDS)
    valid = []
    for t in thresholds:
        pred = (scores < t).astype(int)
        tp = ((pred == 1) & (y_binary == 1)).sum()
        fp = ((pred == 1) & (y_binary == 0)).sum()
        fn = ((pred == 0) & (y_binary == 1)).sum()
        tn = ((pred == 0) & (y_binary == 0)).sum()
        recall = tp / (tp + fn) if (tp + fn) else 0
        fp_rate = fp / (fp + tn) if (fp + tn) else 0
        if recall >= 0.50 and fp_rate <= IF_FP_CEILING:
            valid.append((t, recall, fp_rate))

    if_threshold, if_recall, if_fp = max(valid, key=lambda x: x[1])
    print("=== IF (current-split retrain) — Validation Set ===")
    print(f"Threshold: {if_threshold:.6f}  Recall: {if_recall:.4f}  FP: {if_fp:.4f}")

    if_onnx_path = MODELS_OUT / "if_current_split.onnx"
    if_onnx = to_onnx(iso, X_benign.to_numpy().astype(np.float32), target_opset={"": 17, "ai.onnx.ml": 3})
    if_onnx_path.write_bytes(if_onnx.SerializeToString())
    print(f"ONNX exported: {if_onnx_path} ({if_onnx_path.stat().st_size / 1024:.1f} KB)")

    metadata = {
        "rf": {
            "n_features": X_train.shape[1],
            "macro_f1_val": float(rf_macro_f1),
            "per_class_f1_val": {c: float(f) for c, f in zip(ATTACK_CLASSES, rf_per_class)},
            "onnx_path": str(rf_onnx_path),
            "model_size_bytes": rf_onnx_path.stat().st_size,
        },
        "if": {
            "n_features": X_benign.shape[1],
            "threshold": float(if_threshold),
            "val_recall": float(if_recall),
            "val_fp_rate": float(if_fp),
            "onnx_path": str(if_onnx_path),
            "model_size_bytes": if_onnx_path.stat().st_size,
        },
    }
    path = RESULTS_OUT / "rf_if_current_split_metadata.json"
    path.write_text(json.dumps(metadata, indent=2))
    print(f"Saved: {path}")


if __name__ == "__main__":
    main()
