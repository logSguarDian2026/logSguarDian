#!/usr/bin/env python3
"""
Corpus safety scan for a proposed extractor feature adjustment, same
discipline as the non_form_operator_count precedent (commit 2116c93):
"ADDITIVE only - sqli_operator_count is unchanged, preserving signal for
the 12.53% of sqli corpus rows that depend on it as their sole
SQLi-specific feature (verified via corpus scan, not assumed)."

For sqli_operator_count, quote_count, and base64_like_count: what % of
the relevant attack class(es) depends SOLELY on that one raw feature
(every other feature in the same attack-detection group is zero)? A high
percentage means discounting the feature risks losing real attack
signal outright (the non_form_operator_count precedent found 12.53% for
sqli_operator_count and still shipped it, additively - so "high" here
is relative to that baseline, not an absolute cutoff).

Uses training/data_clean/features.csv (the real, already-extracted
73/75-feature corpus used to train rf_v11) - no re-extraction needed.

Usage:
  python3 check_feature_safety.py
"""
import pandas as pd

FEATURES_CSV = "../data_clean/features.csv"

SQLI_GROUP = [
    "sqli_keyword_count", "sqli_comment_count", "sqli_operator_count",
    "quote_count", "semicolon_count", "parenthesis_count",
    "union_present", "select_present",
]
XSS_GROUP = [
    "xss_marker_count", "html_tag_count", "script_tag_present",
    "js_event_handler_count", "javascript_url_count",
    "alert_function_present", "inline_style_present",
]
PATH_TRAVERSAL_GROUP = [
    "traversal_sequence_count", "path_separator_count",
    "absolute_path_indicator", "sensitive_file_target",
    "sensitive_extension_count", "file_extension_suspicious",
    "dotdot_encoded_count",
]
CMDI_GROUP = [
    "pipe_count", "backtick_count", "shell_command_count",
    "command_separator_count", "redirect_operator_count",
    "dollar_sign_count", "subshell_count", "os_path_indicator",
]
ENCODING_GROUP = [
    "url_encoded_ratio", "encoded_char_freq", "double_encoded_count",
    "hex_escape_count", "unicode_escape_count", "html_entity_count",
    "base64_like_count",
]

CLASS_GROUPS = {
    "sqli": SQLI_GROUP,
    "xss": XSS_GROUP,
    "path_traversal": PATH_TRAVERSAL_GROUP,
    "cmdi": CMDI_GROUP,
}


def pct_sole_dependency(df: pd.DataFrame, label: str, group: list, feature: str) -> dict:
    """% of `label` rows where `feature` > 0 and every other feature in
    `group` is 0 - i.e. this feature is the row's ONLY signal from that
    detection group."""
    sub = df[df["label"] == label]
    n = len(sub)
    if n == 0:
        return {"n": 0, "sole_dependency_pct": 0.0, "sole_dependency_n": 0}
    others = [f for f in group if f != feature]
    mask = (sub[feature] > 0) & (sub[others].sum(axis=1) == 0)
    return {
        "n": n,
        "sole_dependency_n": int(mask.sum()),
        "sole_dependency_pct": float(mask.sum() / n),
    }


def main():
    df = pd.read_csv(FEATURES_CSV)
    print(f"Loaded {len(df)} rows from {FEATURES_CSV}\n")

    print("=" * 70)
    print("sqli_operator_count: % of sqli corpus solely dependent on it")
    print("(precedent baseline from non_form_operator_count's own safety")
    print(" check, commit 2116c93: 12.53%)")
    print("=" * 70)
    r = pct_sole_dependency(df, "sqli", SQLI_GROUP, "sqli_operator_count")
    print(f"  sqli corpus n={r['n']}, sole-dependency n={r['sole_dependency_n']}, "
          f"pct={r['sole_dependency_pct']:.4%}")

    print()
    print("=" * 70)
    print("quote_count: % of sqli corpus solely dependent on it")
    print("=" * 70)
    r = pct_sole_dependency(df, "sqli", SQLI_GROUP, "quote_count")
    print(f"  sqli corpus n={r['n']}, sole-dependency n={r['sole_dependency_n']}, "
          f"pct={r['sole_dependency_pct']:.4%}")

    print()
    print("=" * 70)
    print("base64_like_count: % of each attack class solely dependent on it")
    print("(checked against that class's own group + rest of ENCODING_GROUP,")
    print(" since base64_like_count is a shared Group-3 encoding feature,")
    print(" not owned by any single attack class)")
    print("=" * 70)
    for label, group in CLASS_GROUPS.items():
        combined_group = list(dict.fromkeys(group + ENCODING_GROUP))
        r = pct_sole_dependency(df, label, combined_group, "base64_like_count")
        print(f"  {label:16s} n={r['n']:>7d}  sole-dependency n={r['sole_dependency_n']:>5d}  "
              f"pct={r['sole_dependency_pct']:.4%}")

    print()
    print("=" * 70)
    print("Sanity cross-check: rows where base64_like_count>0 at all (any class)")
    print("=" * 70)
    for label in ["sqli", "xss", "path_traversal", "cmdi", "benign"]:
        sub = df[df["label"] == label]
        n = len(sub)
        nz = int((sub["base64_like_count"] > 0).sum())
        print(f"  {label:16s} n={n:>7d}  base64_like_count>0: {nz:>6d} ({nz/n:.4%})")


if __name__ == "__main__":
    main()
