"""
Shared feature contracts and I/O helpers for the MLP / Autoencoder baselines
(task A34 — comparative benchmark against production rf_v11 / if_v10).

Feature lists are copied from training/notebooks/03_random_forest.ipynb and
04_isolation_forest.ipynb, with one addition: NON_JSON_QUOTE_EXTRA. The
extractor grew a 76th feature (non_json_quote_count) on this branch
(investigate/benign-persona-diversification) as a candidate, not yet
promoted — production rf.onnx/if.onnx still expect 69/63 inputs
(parity_report.json). Dropping it here too keeps MLP/AE on the exact same
input contract as the production ONNX models they are being compared
against; training them on 70/64 dims would make the comparison meaningless.
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent.parent.parent
SPLITS = ROOT / "training" / "splits"
MODELS_OUT = ROOT / "training" / "models" / "baselines"
RESULTS_OUT = ROOT / "training" / "results" / "baselines"

NON_JSON_QUOTE_EXTRA = ["non_json_quote_count"]

RF_DROP_COLS = [
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s", "_source",
    "sample_id", "timestamp", "_row_hash",
] + NON_JSON_QUOTE_EXTRA

IF_META_COLS = [
    "sample_id", "timestamp", "_source", "_row_hash",
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
]
IF_ADDITIONAL_EXCLUDED = [
    "dotdot_encoded_count", "authorization_length", "unusual_headers_count",
    "null_byte_count", "os_path_indicator", "sensitive_file_target",
]
IF_DROP_COLS = IF_META_COLS + IF_ADDITIONAL_EXCLUDED + NON_JSON_QUOTE_EXTRA

TARGET_NAMES = ["benign", "cmdi", "path_traversal", "sqli", "xss"]
ATTACK_CLASSES = ["cmdi", "path_traversal", "sqli", "xss"]

RANDOM_STATE = 42


def load_split(name: str) -> pd.DataFrame:
    return pd.read_parquet(SPLITS / f"{name}.parquet")


def rf_xy(df: pd.DataFrame):
    df = df.drop(columns=[c for c in RF_DROP_COLS if c in df.columns]).copy()
    y = df.pop("label")
    return df, y


def if_xy(df: pd.DataFrame):
    df = df.drop(columns=[c for c in IF_DROP_COLS if c in df.columns]).copy()
    y = df.pop("label")
    return df, y


MODELS_OUT.mkdir(parents=True, exist_ok=True)
RESULTS_OUT.mkdir(parents=True, exist_ok=True)
