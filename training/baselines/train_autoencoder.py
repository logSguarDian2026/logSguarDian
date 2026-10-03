#!/usr/bin/env python3
"""
Autoencoder baseline — direct comparison point for production Isolation
Forest (if_v10). Task A34 (see train_mlp.py's docstring for full context).

Same benign-only training discipline as IF, same 63-dim feature contract as
if.onnx (training/baselines/common.py), same train/val split as notebook 04.
Reconstruction error (MSE) replaces isolation score as the anomaly signal;
same threshold-sweep methodology as notebook 04 (maximize recall subject to
FP <= 0.06), so the reported operating point is directly comparable to
if_v10's own selection criterion, not a cherry-picked best case for either
model.

Architecture: encoder-decoder via MLPRegressor(hidden_layer_sizes=(32, 8,
32)), input=output=63-dim, bottleneck=8 (< 63, satisfies the compression
requirement). Implemented as a regressor trained on X -> X (identity
target) rather than a hand-rolled encoder/decoder pair — same underlying
gradient-descent/backprop training loop sklearn already provides for the
MLP baseline, one fewer new dependency this close to the defense. Features
are standardized (fit on benign train only) before reconstruction — IF does
not need this (path-length invariant, tree-based) but reconstruction-error
autoencoders are scale-sensitive; undocumented, this would unfairly
penalize the AE on high-variance features.

Usage:
    python3 training/baselines/train_autoencoder.py
"""
import json
import time

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from skl2onnx import to_onnx
import onnxruntime as ort

from common import load_split, if_xy, RANDOM_STATE, MODELS_OUT, RESULTS_OUT

HIDDEN_LAYERS = (32, 8, 32)
FP_CEILING = 0.06
N_THRESHOLDS = 300
N_LATENCY_SAMPLES = 2000


def reconstruction_error(model: MLPRegressor, X: np.ndarray) -> np.ndarray:
    X_hat = model.predict(X)
    return np.mean((X - X_hat) ** 2, axis=1)


def measure_onnx_latency(onnx_path, X_sample: np.ndarray) -> dict:
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
    return {"p50_ms": latencies_ms[int(n * 0.50)], "p95_ms": latencies_ms[int(n * 0.95)], "n_samples": n}


def main():
    train_df = load_split("train")
    val_df = load_split("val")

    X_train, y_train = if_xy(train_df)
    X_val, y_val = if_xy(val_df)

    X_benign = X_train[y_train == "benign"].to_numpy().astype(np.float32)
    print(f"Benign-only training samples: {X_benign.shape[0]:,}")
    print(f"Feature columns: {X_benign.shape[1]}")
    print("CRITICAL: Autoencoder trains on benign only — never on attack samples (mirrors IF).")

    scaler = StandardScaler().fit(X_benign)
    X_benign_scaled = scaler.transform(X_benign)

    ae = MLPRegressor(
        hidden_layer_sizes=HIDDEN_LAYERS,
        activation="relu",
        solver="adam",
        alpha=1e-4,
        max_iter=300,
        early_stopping=True,
        n_iter_no_change=10,
        random_state=RANDOM_STATE,
    )
    ae.fit(X_benign_scaled, X_benign_scaled)

    X_val_np = X_val.to_numpy().astype(np.float32)
    X_val_scaled = scaler.transform(X_val_np)
    scores = reconstruction_error(ae, X_val_scaled)
    y_binary = (y_val != "benign").astype(int).to_numpy()

    # Quantile-spaced, not linspace(min, max): reconstruction-error MSE is
    # heavily right-skewed (a handful of extreme-error attacks dominate the
    # range), so linear spacing (which works fine for IF's bounded isolation
    # score, see notebook 04) wastes nearly all 300 thresholds deep in the
    # outlier tail and never samples the low-FP region where IF operates.
    thresholds = np.quantile(scores, np.linspace(0.0, 1.0, N_THRESHOLDS))
    recalls, fp_rates = [], []
    for t in thresholds:
        predicted_attack = (scores > t).astype(int)  # high reconstruction error = anomaly
        tp = ((predicted_attack == 1) & (y_binary == 1)).sum()
        fp = ((predicted_attack == 1) & (y_binary == 0)).sum()
        fn = ((predicted_attack == 0) & (y_binary == 1)).sum()
        tn = ((predicted_attack == 0) & (y_binary == 0)).sum()
        recalls.append(tp / (tp + fn) if (tp + fn) > 0 else 0)
        fp_rates.append(fp / (fp + tn) if (fp + tn) > 0 else 0)

    valid = [(t, r, f) for t, r, f in zip(thresholds, recalls, fp_rates) if f <= FP_CEILING]
    if not valid:
        print(f"WARNING: no threshold satisfies FP <= {FP_CEILING}")
        best_threshold, best_recall, best_fp = None, 0.0, 1.0
    else:
        best_threshold, best_recall, best_fp = max(valid, key=lambda x: x[1])
        print(f"Selected threshold : {best_threshold:.6f}")
        print(f"Recall             : {best_recall:.4f}")
        print(f"FP rate            : {best_fp:.4f}")

    onnx_path = MODELS_OUT / "autoencoder.onnx"
    onnx_model = to_onnx(ae, X_benign_scaled.astype(np.float32), target_opset=17)
    onnx_path.write_bytes(onnx_model.SerializeToString())
    model_size_bytes = onnx_path.stat().st_size
    print(f"ONNX exported: {onnx_path} ({model_size_bytes / 1024:.1f} KB)")

    # Latency measured on the encoder/decoder pass only (matches production
    # if.onnx, which likewise excludes the threshold comparison itself).
    latency = measure_onnx_latency(onnx_path, X_val_scaled)
    print(f"Latency p50: {latency['p50_ms']:.4f} ms  p95: {latency['p95_ms']:.4f} ms")

    metadata = {
        "architecture": f"MLPRegressor{HIDDEN_LAYERS} (encoder-decoder, bottleneck=8), StandardScaler, X->X reconstruction",
        "n_features": X_benign.shape[1],
        "n_params_approx": sum(w.size for w in ae.coefs_) + sum(b.size for b in ae.intercepts_),
        "trained_on": "benign_only",
        "fp_ceiling": FP_CEILING,
        "selected_threshold": None if best_threshold is None else float(best_threshold),
        "val_recall": float(best_recall),
        "val_fp_rate": float(best_fp),
        "model_size_bytes": model_size_bytes,
        "latency_p50_ms": latency["p50_ms"],
        "latency_p95_ms": latency["p95_ms"],
    }
    metadata_path = RESULTS_OUT / "autoencoder_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"Saved: {metadata_path}")

    # Scaler params saved alongside so evaluate_test_once.py can apply the
    # identical benign-fit standardization to the test set later.
    scaler_path = MODELS_OUT / "autoencoder_scaler.json"
    scaler_path.write_text(json.dumps({
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": X_train.columns.tolist(),
    }))
    print(f"Saved: {scaler_path}")


if __name__ == "__main__":
    main()
