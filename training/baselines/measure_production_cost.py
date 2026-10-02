#!/usr/bin/env python3
"""
Measures RF / IF inference latency and serialized size, using the same
methodology as train_mlp.py / train_autoencoder.py, so the comparative
table's cost column is apples-to-apples across all four models.

Uses the current-split retrains from train_rf_if_current_split.py, not the
committed production rf.onnx/if.onnx — those were trained on an older data
snapshot (see that script's docstring) and would make this a comparison
across two different corpora, not just two different architectures. Model
size/latency for a 30-tree RF / 200-tree IF is not meaningfully sensitive
to which snapshot trained it, so this is still representative of
production cost.

Uses val.parquet inputs only (no labels needed for a latency measurement,
and the locked test set stays untouched — R2). Safe to re-run any number of
times, unlike evaluate_test_once.py.
"""
import json
import time

import numpy as np
import onnxruntime as ort

from common import load_split, rf_xy, if_xy, MODELS_OUT, RESULTS_OUT

N_LATENCY_SAMPLES = 2000
RF_ONNX = MODELS_OUT / "rf_current_split.onnx"
IF_ONNX = MODELS_OUT / "if_current_split.onnx"


def measure(onnx_path, X_sample: np.ndarray) -> dict:
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name

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
        "model_size_bytes": onnx_path.stat().st_size,
    }


def main():
    val_df = load_split("val")
    X_val_rf, _ = rf_xy(val_df)
    X_val_if, _ = if_xy(val_df)

    rf_cost = measure(RF_ONNX, X_val_rf.to_numpy())
    if_cost = measure(IF_ONNX, X_val_if.to_numpy())

    print("RF (rf.onnx, production):", rf_cost)
    print("IF (if.onnx, production):", if_cost)

    out = {"rf_v11": rf_cost, "if_v10": if_cost}
    path = RESULTS_OUT / "production_cost.json"
    path.write_text(json.dumps(out, indent=2))
    print(f"Saved: {path}")


if __name__ == "__main__":
    main()
