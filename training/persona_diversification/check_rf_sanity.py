#!/usr/bin/env python3
"""
Automated sanity floor. Re-run (post extractor-fix candidate) against the
FIXED candidate rf.onnx (rf_candidate.onnx, 70 features: base64_like_count
regex fix + non_json_quote_count) and report % classified benign. Pure
inference, read-only against unified.jsonl/label_map.yaml/models - no
retrain triggered by this script, no integration.

Files live in training/persona_diversification/generated_data/ (moved out
of training/data_clean/ after discovering unify.py globs every *.jsonl in
that directory with no label_map gate - leaving them there would silently
fold them into the next real retrain's corpus).

Pipeline per file (matches training/ct_pipeline.py's real path, not a
re-implementation): node extractor CLI -> features.csv -> drop the same
DROP_COLS notebook 03 drops (status_code + 5 always-zero temporal
features) -> onnxruntime inference against the given rf.onnx.

Usage:
  python3 check_rf_sanity.py [--model path/to/rf.onnx] > results/persona_rf_sanity_report_v2.json
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
DATA_CLEAN = Path(__file__).resolve().parent / "generated_data"
EXTRACTOR_CLI = REPO / "packages" / "extractor" / "dist" / "cli.js"
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--model", type=str, default=str(REPO / "training" / "models" / "rf.onnx"))
_args, _ = _parser.parse_known_args()
RF_ONNX = Path(_args.model)

PERSONAS = ["dashboard", "api_only", "admin_panel"]
SCALES = [200, 500, 1000, 2000]

# Same DROP_COLS as training/notebooks/03_random_forest.ipynb.
DROP_COLS = [
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s", "_source",
    "sample_id", "timestamp", "_row_hash",
]


def extract_features(jsonl_path: Path, tmp_dir: Path) -> pd.DataFrame:
    csv_path = tmp_dir / (jsonl_path.stem + "_features.csv")
    result = subprocess.run(
        ["node", str(EXTRACTOR_CLI), str(jsonl_path), str(csv_path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"extractor CLI failed on {jsonl_path}: {result.stderr}")
    return pd.read_csv(csv_path)


def main():
    sess = ort.InferenceSession(str(RF_ONNX))
    input_name = sess.get_inputs()[0].name

    report = {"model": str(RF_ONNX), "results": {}}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for persona in PERSONAS:
            for scale in SCALES:
                fname = f"synthetic_{persona}_{scale}.jsonl"
                fpath = DATA_CLEAN / fname
                if not fpath.exists():
                    print(f"MISSING: {fpath}", file=sys.stderr)
                    continue

                print(f"scoring {fname}...", file=sys.stderr)
                df = extract_features(fpath, tmp_dir)
                labels = df.pop("label")
                df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

                X = df.to_numpy(dtype=np.float32)
                outputs = sess.run(None, {input_name: X})
                predicted_labels = outputs[0]

                n = len(predicted_labels)
                pct_benign = float(sum(1 for p in predicted_labels if p == "benign") / n)
                class_counts = {}
                for p in predicted_labels:
                    class_counts[p] = class_counts.get(p, 0) + 1

                key = f"{persona}_{scale}"
                report["results"][key] = {
                    "n": n,
                    "pct_benign": pct_benign,
                    "predicted_class_counts": class_counts,
                }
                print(f"  {key}: pct_benign={pct_benign:.4%} counts={class_counts}", file=sys.stderr)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
