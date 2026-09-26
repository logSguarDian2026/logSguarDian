"""
One-time R2 test-set read for rf_v11 / if_v10 — the models actually
published in npm (see training/models/parity_report.json).

Why this script exists: every metric previously cited in
docs/decision-policy.md sec 2.1 (and mirrored into
training/models/class_metrics.json) comes from rf_v3, two generations
behind the published rf_v11/if_v10. No code in this repo has ever read
the locked test set before — the one precedent,
training/results/v10_test_results.json, was produced by an ad-hoc script
that was never committed. This script is that missing, reproducible
artifact.

Output: training/results/v11_test_results.json (NOT training/models/ —
ct_pipeline.py runs `git checkout -- training/models/` in the CT
pipeline and would silently discard anything written there).

Design decisions (see .claude-plan.md "Fase 3" for the full rationale):

  1. The test.lock.sha256 gate is recomputed and checked FIRST. If the
     restored test.parquet doesn't hash-match the committed lock, this
     script aborts — reading an unverified partition and calling it "the
     locked test set" would be indefensible in front of a committee.

  2. Inference goes through rf.onnx / if.onnx via onnxruntime, not the
     .pkl files. The ONNX files are the exact binaries bundled into the
     published npm package; reading the .pkl would validate a different
     artifact than the one users actually run.

  3. Feature selection is done by explicit name lookup against the
     canonical FEATURE_NAMES list (copied verbatim from
     packages/extractor/src/index.ts — Python never recomputes features,
     per R1, but it still needs the same *order* the ONNX graphs were
     built with), not by "drop the known-bad columns and keep
     whatever's left". This matters concretely here: the restored
     train/val/test.parquet carry a stray extra column,
     `non_json_quote_count`, that is NOT part of the current 75-feature
     canonical vector (it doesn't appear anywhere in packages/extractor
     source, confirmed via `git log --all -S`). A naive "drop the 6/12
     excluded columns, keep the rest" (the approach
     training/notebooks/05_onnx_export.ipynb's own cells use) produces
     70 RF columns / 64 IF columns here — one too many in both cases —
     which would either crash onnxruntime on a shape mismatch or, worse,
     silently misalign every downstream feature by one position. Explicit
     FEATURE_NAMES selection sidesteps this entirely and is verified
     against parity_report.json's rf_n_features/if_n_features below
     before any inference runs.

  4. AUC-ROC (One-vs-Rest, sklearn's roc_auc_score with
     multi_class="ovr", average=None) is new code — there is no
     precedent for it anywhere in this repo (zero prior occurrences of
     roc_auc_score).

  5. The IF threshold (0.00806713286301003, from
     training/models/if_v10_metadata.json) is used as-is. It is NEVER
     recalibrated against test — doing so would violate the R2
     one-time-read discipline the whole point of this script is to
     uphold.

Usage:
    python training/evaluate_test.py
"""

import hashlib
import json
import sys
from datetime import date
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import label_binarize

ROOT = Path(__file__).parent.parent
SPLITS_DIR = ROOT / "training" / "splits"
MODELS_DIR = ROOT / "training" / "models"
RESULTS_DIR = ROOT / "training" / "results"

TEST_PARQUET = SPLITS_DIR / "test.parquet"
TEST_LOCK = SPLITS_DIR / "test.lock.sha256"
RF_ONNX = MODELS_DIR / "rf.onnx"
IF_ONNX = MODELS_DIR / "if.onnx"
IF_METADATA = MODELS_DIR / "if_v10_metadata.json"
PARITY_REPORT = MODELS_DIR / "parity_report.json"

OUTPUT_PATH = RESULTS_DIR / "v11_test_results.json"
CLASS_METRICS_PATH = MODELS_DIR / "class_metrics.json"

# Canonical 75-feature order, copied verbatim from
# packages/extractor/src/index.ts (FEATURE_NAMES). Python never
# recomputes features (R1) — this is a name/order reference only, used
# to select and order columns already produced by the TS extractor CLI.
FEATURE_NAMES = [
    # Grupo 1: longitudes (10)
    "payload_length", "payload_entropy", "uri_length", "path_length",
    "query_string_length", "body_length", "body_entropy",
    "path_depth", "query_param_count", "fragment_present",
    # Grupo 2: composicion de caracteres (8)
    "special_char_ratio", "numeric_char_ratio", "uppercase_ratio",
    "whitespace_count", "newline_char_count", "null_byte_count",
    "extended_ascii_ratio", "payload_token_count",
    # Grupo 3: encoding (7)
    "url_encoded_ratio", "encoded_char_freq", "double_encoded_count",
    "hex_escape_count", "unicode_escape_count", "html_entity_count", "base64_like_count",
    # Grupo 4: SQLi (10)
    "sqli_keyword_count", "sqli_keyword_density", "sqli_comment_count",
    "sqli_operator_count", "non_form_operator_count", "quote_count",
    "semicolon_count", "parenthesis_count", "union_present", "select_present",
    # Grupo 5: XSS (9)
    "xss_marker_count", "xss_marker_density", "html_tag_count",
    "script_tag_present", "js_event_handler_count", "javascript_url_count",
    "html_entity_density", "alert_function_present", "inline_style_present",
    # Grupo 6: Path Traversal (7)
    "traversal_sequence_count", "path_separator_count", "absolute_path_indicator",
    "sensitive_file_target", "sensitive_extension_count", "file_extension_suspicious",
    "dotdot_encoded_count",
    # Grupo 7: Command Injection (10)
    "pipe_count", "backtick_count", "shell_command_count",
    "command_separator_count", "redirect_operator_count",
    "dollar_sign_count", "subshell_count", "os_path_indicator",
    "distinct_shell_command_count", "shell_to_path_ratio",
    # Grupo 8: HTTP request (9)
    "method_is_get", "method_is_post", "ua_present", "ua_length",
    "ua_suspicious", "content_type_encoded", "authorization_length",
    "unusual_headers_count", "status_code",
    # Grupo 9: temporal (5) - siempre 0, requiere estado entre requests
    "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
]
assert len(FEATURE_NAMES) == 75, f"Expected 75 canonical features, got {len(FEATURE_NAMES)}"

# RF excludes these 6 runtime-unavailable features (packages/core/src/worker.ts
# EXCLUDED_NAMES / docs/feature-spec.md).
RF_EXCLUDED = {
    "status_code", "req_count_1s", "req_count_5s",
    "req_count_60s", "error_rate_4xx_60s", "endpoint_diversity_60s",
}

# IF excludes RF_EXCLUDED plus these 6 additional near-zero-variance
# features (packages/core/src/worker.ts IF_ADDITIONAL_EXCLUDED).
IF_ADDITIONAL_EXCLUDED = {
    "dotdot_encoded_count", "authorization_length", "unusual_headers_count",
    "null_byte_count", "os_path_indicator", "sensitive_file_target",
}

RF_FEATURE_NAMES = [n for n in FEATURE_NAMES if n not in RF_EXCLUDED]
IF_FEATURE_NAMES = [n for n in RF_FEATURE_NAMES if n not in IF_ADDITIONAL_EXCLUDED]


def row_hash(row: pd.Series) -> str:
    """Same fallback logic as training/split.py:46-58."""
    if "_row_hash" in row.index and row["_row_hash"]:
        return str(row["_row_hash"])
    key = (
        str(row.get("path", "")) + "|"
        + str(row.get("query", "")) + "|"
        + str(row.get("body", "") or "") + "|"
        + str(row.get("label", ""))
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_lock(df_test: pd.DataFrame) -> str:
    if not TEST_LOCK.exists():
        print(f"ABORT: lock file not found at {TEST_LOCK}", file=sys.stderr)
        sys.exit(1)

    expected = TEST_LOCK.read_text(encoding="utf-8").strip()
    hashes = sorted(df_test.apply(row_hash, axis=1).tolist())
    combined = "\n".join(hashes)
    recomputed = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    print(f"Lock file        : {TEST_LOCK}")
    print(f"Expected hash     : {expected}")
    print(f"Recomputed hash   : {recomputed}")

    if recomputed != expected:
        print(
            "\nABORT: recomputed hash does NOT match test.lock.sha256.\n"
            "The restored test.parquet is not the partition that was locked "
            "for rf_v11/if_v10 — a test-set read against it would be invalid. "
            "Stop here; do not re-lock or proceed.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Lock verification : MATCH\n")
    return recomputed


def load_feature_matrix(df: pd.DataFrame, feature_names: list[str]) -> np.ndarray:
    missing = [n for n in feature_names if n not in df.columns]
    if missing:
        raise ValueError(f"Missing expected feature columns: {missing}")
    return df[feature_names].to_numpy(dtype=np.float32)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("R2 one-time test-set read — rf_v11 / if_v10")
    print("=" * 70)

    print(f"\nLoading {TEST_PARQUET} ...")
    df_test = pd.read_parquet(TEST_PARQUET)
    print(f"  Loaded {len(df_test):,} rows, {len(df_test.columns)} columns")

    # --- 1. Verify the lock (gate) ---
    print("\n--- Step 1: verify test.lock.sha256 ---")
    lock_hash = verify_lock(df_test)

    # --- 2. Load parity report + ONNX sessions ---
    print("--- Step 2: load ONNX models ---")
    parity = json.loads(PARITY_REPORT.read_text(encoding="utf-8"))
    if_meta = json.loads(IF_METADATA.read_text(encoding="utf-8"))

    rf_classes_order = parity["rf_classes"]  # ["benign","cmdi","path_traversal","sqli","xss"]
    rf_onnx_output_index = parity["rf_onnx_output_index"]
    if_onnx_output_index = parity["if_onnx_output_index"]
    if_threshold = if_meta["threshold"]

    rf_sess = ort.InferenceSession(str(RF_ONNX))
    if_sess = ort.InferenceSession(str(IF_ONNX))
    print(f"  rf.onnx  : input {rf_sess.get_inputs()[0].shape}")
    print(f"  if.onnx  : input {if_sess.get_inputs()[0].shape}")

    # --- 3. Build the two feature matrices, verify column counts ---
    print("\n--- Step 3: build RF (69) / IF (63) feature matrices ---")
    print(f"  RF feature count : {len(RF_FEATURE_NAMES)} (expected {parity['rf_n_features']})")
    print(f"  IF feature count : {len(IF_FEATURE_NAMES)} (expected {parity['if_n_features']})")
    assert len(RF_FEATURE_NAMES) == parity["rf_n_features"], (
        f"RF feature count mismatch: {len(RF_FEATURE_NAMES)} != {parity['rf_n_features']}"
    )
    assert len(IF_FEATURE_NAMES) == parity["if_n_features"], (
        f"IF feature count mismatch: {len(IF_FEATURE_NAMES)} != {parity['if_n_features']}"
    )

    X_rf = load_feature_matrix(df_test, RF_FEATURE_NAMES)
    X_if = load_feature_matrix(df_test, IF_FEATURE_NAMES)
    y_true = df_test["label"].to_numpy()

    print(f"  X_rf shape: {X_rf.shape}, X_if shape: {X_if.shape}")

    # --- 4. RF inference + metrics ---
    print("\n--- Step 4: RF inference ---")
    rf_out = rf_sess.run(None, {"float_input": X_rf})
    rf_pred_labels = rf_out[0]  # string labels, shape [N]
    rf_probs = rf_out[rf_onnx_output_index]  # shape [N, 5]

    rf_report = classification_report(
        y_true, rf_pred_labels,
        labels=rf_classes_order,
        output_dict=True, zero_division=0,
    )
    rf_macro_f1 = rf_report["macro avg"]["f1-score"]

    print(classification_report(y_true, rf_pred_labels, labels=rf_classes_order, zero_division=0))

    # AUC-ROC, One-vs-Rest, per class. New code — no precedent in this repo.
    y_true_bin = label_binarize(y_true, classes=rf_classes_order)
    auc_per_class_arr = roc_auc_score(
        y_true_bin, rf_probs, multi_class="ovr", average=None
    )
    rf_auc_roc_per_class = {
        cls: float(auc) for cls, auc in zip(rf_classes_order, auc_per_class_arr)
    }
    print("AUC-ROC (OvR) per class:")
    for cls, auc in rf_auc_roc_per_class.items():
        print(f"  {cls:16s}: {auc:.4f}")

    # --- 5. IF inference + metrics (frozen threshold, never recalibrated) ---
    print("\n--- Step 5: IF inference (frozen threshold, no recalibration) ---")
    if_out = if_sess.run(None, {"float_input": X_if})
    if_scores = if_out[if_onnx_output_index].flatten()  # decision_function-style scores

    y_is_attack = (y_true != "benign").astype(int)
    if_pred_attack = (if_scores < if_threshold).astype(int)

    tp = int(np.sum((if_pred_attack == 1) & (y_is_attack == 1)))
    fn = int(np.sum((if_pred_attack == 0) & (y_is_attack == 1)))
    fp = int(np.sum((if_pred_attack == 1) & (y_is_attack == 0)))
    tn = int(np.sum((if_pred_attack == 0) & (y_is_attack == 0)))

    if_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if_fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    if_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    print(f"  threshold   : {if_threshold}")
    print(f"  TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  recall      : {if_recall:.4f}")
    print(f"  fp_rate     : {if_fp_rate:.4f}")
    print(f"  precision   : {if_precision:.4f}")

    if_per_class_recall = {}
    for cls in [c for c in rf_classes_order if c != "benign"]:
        mask = y_true == cls
        n = int(mask.sum())
        if n == 0:
            continue
        recall_cls = float(np.sum(if_pred_attack[mask] == 1) / n)
        if_per_class_recall[cls] = recall_cls
        print(f"  recall[{cls:16s}]: {recall_cls:.4f} (n={n})")

    # --- 6. Assemble output JSON ---
    print("\n--- Step 6: writing results ---")

    # Checksum manifest: lock_hash above verifies row *identity* (which
    # requests are in test) and is invariant to feature-value changes by
    # design (see split.py/row_hash) — it can match even when the extractor
    # that computed the feature columns has changed underneath it. This
    # block additionally fixes the exact byte-content of every artifact this
    # evaluation actually read, so a later reader can verify "is this still
    # the same model+test-set pairing this metric describes" without relying
    # on file mtimes or assuming nothing was silently regenerated (the gap
    # that let a candidate retrain orphan the original rf_v11/if_v10 numbers).
    artifact_checksums = {
        "test_parquet_sha256": hashlib.sha256(TEST_PARQUET.read_bytes()).hexdigest(),
        "rf_onnx_sha256": hashlib.sha256(RF_ONNX.read_bytes()).hexdigest(),
        "if_onnx_sha256": hashlib.sha256(IF_ONNX.read_bytes()).hexdigest(),
    }

    results = {
        "lock_verified": True,
        "lock_hash": lock_hash,
        "artifact_checksums": artifact_checksums,
        "model": "rf_v11",
        "if_companion_model": "if_v10",
        "eval_set": "test",
        "eval_date": date.today().isoformat(),
        "eval_note": (
            "R2 one-time locked test-set read against the ONNX models actually "
            "published in npm (rf.onnx / if.onnx via onnxruntime, not the .pkl "
            "files). Produced by training/evaluate_test.py. test.lock.sha256 "
            "verified to match before any inference ran (see lock_hash above). "
            "This is the first test-set read for rf_v11/if_v10; prior figures "
            "in docs/decision-policy.md sec 2.1 are rf_v3, two generations "
            "behind the published model, and are not comparable to these."
        ),
        "n_test_rows": int(len(df_test)),
        "rf_n_features": len(RF_FEATURE_NAMES),
        "if_n_features": len(IF_FEATURE_NAMES),
        "rf_classification_report": rf_report,
        "rf_macro_f1": float(rf_macro_f1),
        "rf_auc_roc_per_class": rf_auc_roc_per_class,
        "rf_auc_roc_method": "one-vs-rest (sklearn.metrics.roc_auc_score, multi_class='ovr', average=None)",
        "if_model": "if_v10",
        "if_threshold": if_threshold,
        "if_threshold_source": "training/models/if_v10_metadata.json (frozen; not recalibrated against test)",
        "if_test_recall": float(if_recall),
        "if_test_fp_rate": float(if_fp_rate),
        "if_test_precision": float(if_precision),
        "if_test_per_class_recall": if_per_class_recall,
        "if_test_confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
    }

    OUTPUT_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote: {OUTPUT_PATH}")

    # --- 7. Regenerate class_metrics.json (RF per-class metrics) ---
    class_metrics = {
        "model": "rf_v11",
        "n_estimators": 30,
        "max_depth": 25,
        "eval_set": "test",
        "eval_note": (
            f"R2 one-time read of the locked test set ({lock_hash[:16]}...), "
            f"evaluated on {date.today().isoformat()} against rf.onnx (rf_v11), "
            "the model actually published in npm. Supersedes the rf_v3 figures "
            "previously frozen here since 2026-06 (see git history) and cited "
            "in docs/decision-policy.md sec 2.1 -- those numbers were for a "
            "model two generations behind the one shipped. Test set read "
            "exactly once for this evaluation; no retraining after observing "
            "these numbers."
        ),
        "classes": {
            cls: {
                "f1": round(float(rf_report[cls]["f1-score"]), 4),
                "precision": round(float(rf_report[cls]["precision"]), 4),
                "recall": round(float(rf_report[cls]["recall"]), 4),
                "auc_roc": round(float(rf_auc_roc_per_class[cls]), 4),
            }
            for cls in rf_classes_order
        },
        "macro_f1": round(float(rf_macro_f1), 4),
    }
    CLASS_METRICS_PATH.write_text(json.dumps(class_metrics, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote: {CLASS_METRICS_PATH}")

    print("\nDone.")


if __name__ == "__main__":
    main()
