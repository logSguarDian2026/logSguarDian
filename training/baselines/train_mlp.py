#!/usr/bin/env python3
"""
MLP baseline — direct comparison point for production Random Forest (rf_v11).

Task A34: back the Marco Teorico Section 6.8 architecture decision (RF/IF
over MLP/autoencoder) with measured numbers from this project's own data,
not just a citation to Berman et al.'s general finding.

Trains on the exact same 69-dim feature contract as rf.onnx (see
training/baselines/common.py), same train/val split as notebook 03. Only
touches train.parquet and val.parquet — the locked test set is read once,
later, by evaluate_test_once.py, together with RF/IF/Autoencoder.

Architecture: MLPClassifier(hidden_layer_sizes=(64, 32)). Two hidden layers,
~7.5K trainable parameters (69*64+64 + 64*32+32 + 32*5+5 = 7,141) — same
order of magnitude a real deployment would size for a 5ms p95 latency
budget (see Marco Teorico Section 6.8), not an oversized network picked to
either flatter or sandbag the comparison. adam solver + backprop, matching
Section 6.8's "descenso de gradiente y retropropagacion" description.

Usage:
    python3 training/baselines/train_mlp.py
"""
import json
import time

import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import f1_score, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as ort

from common import load_split, rf_xy, TARGET_NAMES, ATTACK_CLASSES, RANDOM_STATE, MODELS_OUT, RESULTS_OUT

HIDDEN_LAYERS = (64, 32)
N_LATENCY_SAMPLES = 2000


def measure_onnx_latency(onnx_path, X_sample: np.ndarray) -> dict:
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name

    # Warm up (first calls include session/graph-optimization warmup cost,
    # not representative of steady-state per-request latency).
    for i in range(50):
        row = X_sample[i % len(X_sample):i % len(X_sample) + 1]
        sess.run(None, {input_name: row.astype(np.float32)})

    latencies_ms = []
    for i in range(N_LATENCY_SAMPLES):
        row = X_sample[i % len(X_sample):i % len(X_sample) + 1].astype(np.float32)
        t0 = time.perf_counter()
        sess.run(None, {input_name: row})
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    latencies_ms.sort()
    n = len(latencies_ms)
    return {
        "p50_ms": latencies_ms[int(n * 0.50)],
        "p95_ms": latencies_ms[int(n * 0.95)],
        "n_samples": n,
    }


def main():
    train_df = load_split("train")
    val_df = load_split("val")

    X_train, y_train = rf_xy(train_df)
    X_val, y_val = rf_xy(val_df)

    print(f"Train: {X_train.shape}  Val: {X_val.shape}")

    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("mlp", MLPClassifier(
            hidden_layer_sizes=HIDDEN_LAYERS,
            activation="relu",
            solver="adam",
            alpha=1e-4,
            max_iter=200,
            early_stopping=True,
            n_iter_no_change=10,
            random_state=RANDOM_STATE,
        )),
    ])
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_val)
    print("=== MLP baseline — Validation Set ===")
    print(classification_report(y_val, y_pred, target_names=TARGET_NAMES))

    macro_f1 = f1_score(y_val, y_pred, average="macro")
    per_class = f1_score(y_val, y_pred, average=None, labels=ATTACK_CLASSES)
    print(f"Macro F1: {macro_f1:.4f}")

    onnx_path = MODELS_OUT / "mlp.onnx"
    onnx_model = to_onnx(
        clf, X_train.to_numpy().astype(np.float32),
        target_opset=17,
        options={id(clf.steps[-1][1]): {"zipmap": False}},
    )
    onnx_path.write_bytes(onnx_model.SerializeToString())
    model_size_bytes = onnx_path.stat().st_size
    print(f"ONNX exported: {onnx_path} ({model_size_bytes / 1024:.1f} KB)")

    latency = measure_onnx_latency(onnx_path, X_val.to_numpy())
    print(f"Latency p50: {latency['p50_ms']:.4f} ms  p95: {latency['p95_ms']:.4f} ms")

    metadata = {
        "architecture": f"MLPClassifier{HIDDEN_LAYERS}, StandardScaler + adam + backprop",
        "n_features": X_train.shape[1],
        "n_params_approx": sum(w.size for w in clf.named_steps["mlp"].coefs_)
        + sum(b.size for b in clf.named_steps["mlp"].intercepts_),
        "macro_f1_val": float(macro_f1),
        "per_class_f1_val": {c: float(f) for c, f in zip(ATTACK_CLASSES, per_class)},
        "model_size_bytes": model_size_bytes,
        "latency_p50_ms": latency["p50_ms"],
        "latency_p95_ms": latency["p95_ms"],
    }
    metadata_path = RESULTS_OUT / "mlp_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"Saved: {metadata_path}")


if __name__ == "__main__":
    main()
