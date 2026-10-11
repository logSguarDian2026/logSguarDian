#!/usr/bin/env python3
"""
Identity audit of the rf_v11 data and model artifacts.

Records hashes, row counts, class counts per source and an ONNX comparison on
the validation split. It never computes a test-set metric and never reads
test predictions. Output: training/audit/identity_audit.json.

Usage:
    python3 training/audit/identity_audit.py
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
SPLITS_DIR = ROOT / "training" / "splits"
DATA_DIR = ROOT / "training" / "data_clean"
MODELS_DIR = ROOT / "training" / "models"
EVALUATE_TEST_PATH = ROOT / "training" / "evaluate_test.py"
OUTPUT_PATH = Path(__file__).resolve().parent / "identity_audit.json"

RF_PRODUCTION_ONNX = MODELS_DIR / "rf.onnx"
RF_CURRENT_SPLIT_ONNX = MODELS_DIR / "baselines" / "rf_current_split.onnx"
PARQUET_FILES = {
    "train": SPLITS_DIR / "train.parquet",
    "val": SPLITS_DIR / "val.parquet",
    "test": SPLITS_DIR / "test.parquet",
    "features": DATA_DIR / "features.parquet",
}
TEST_LOCK_PATH = SPLITS_DIR / "test.lock.sha256"
CMDI_LABEL = "cmdi"
SYNTHETIC_SOURCE_PREFIX = "synthetic_"


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parquet_identity(path: Path) -> dict:
    return {
        "sha256": sha256_of_file(path),
        "rows": pq.ParquetFile(path).metadata.num_rows,
    }


def load_evaluate_test_module():
    spec = importlib.util.spec_from_file_location("evaluate_test", EVALUATE_TEST_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cmdi_source_counts(path: Path) -> dict:
    frame = pd.read_parquet(path, columns=["label", "_source"])
    cmdi_sources = frame.loc[frame["label"] == CMDI_LABEL, "_source"]
    per_source = {str(source): int(count) for source, count in cmdi_sources.value_counts().items()}
    synthetic = int(cmdi_sources.str.startswith(SYNTHETIC_SOURCE_PREFIX).sum())
    return {
        "cmdi_rows": int(len(cmdi_sources)),
        "cmdi_synthetic_rows": synthetic,
        "cmdi_rows_by_source": dict(sorted(per_source.items())),
    }


def run_onnx(model_path: Path, features: np.ndarray) -> np.ndarray:
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    _, probabilities = session.run(None, {input_name: features})
    return np.asarray(probabilities, dtype=np.float64)


def compare_onnx_models(features: np.ndarray) -> dict:
    production = run_onnx(RF_PRODUCTION_ONNX, features)
    current_split = run_onnx(RF_CURRENT_SPLIT_ONNX, features)
    argmax_differences = int(np.sum(np.argmax(production, axis=1) != np.argmax(current_split, axis=1)))
    max_probability_difference = float(np.max(np.abs(production - current_split)))
    return {
        "eval_set": "val",
        "rows": int(features.shape[0]),
        "argmax_differences": argmax_differences,
        "max_abs_probability_difference": max_probability_difference,
        "rf_onnx_sha256": sha256_of_file(RF_PRODUCTION_ONNX),
        "rf_current_split_onnx_sha256": sha256_of_file(RF_CURRENT_SPLIT_ONNX),
    }


def validation_rf_features(evaluate_test) -> np.ndarray:
    val_frame = pd.read_parquet(PARQUET_FILES["val"])
    return evaluate_test.load_feature_matrix(val_frame, evaluate_test.RF_FEATURE_NAMES)


def build_report() -> dict:
    evaluate_test = load_evaluate_test_module()
    return {
        "parquet": {name: parquet_identity(path) for name, path in PARQUET_FILES.items()},
        "test_lock_sha256_file": TEST_LOCK_PATH.read_text(encoding="utf-8").strip(),
        "test_cmdi": cmdi_source_counts(PARQUET_FILES["test"]),
        "onnx_comparison_on_val": compare_onnx_models(validation_rf_features(evaluate_test)),
    }


def main() -> None:
    report = build_report()
    OUTPUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
