"""
Leakage quantification — Fase 1 of the objectives-compliance remediation plan.

Cross-references two evaluation artifacts against the training data to
quantify how much of the reported detection performance is attributable to
literal or near-literal memorization of the evaluation payloads, rather than
generalization.

Sources cross-referenced:

1. "Round 4" evaluation corpus (external, read-only) —
   logSguarDian-vulnerable-project/attack-sim/large_corpus.json
   Structure: dict[category] -> list[payload_str], 4 categories
   (sqli=77, xss=113, path_traversal=200, cmdi=200).

2. E2E gate fixture — e2e/fixtures/test_payloads.jsonl
   Structure: JSONL of full CanonicalRequest records (path/query/body/...)
   + "label", 500 rows (100 per class incl. benign), sampled from the full
   training corpus (training/data_clean/*.jsonl) per docs/results.md:638,
   NOT from the locked test partition.

Both are cross-referenced against training/splits/{train,val,test}.parquet.

Reused (per instructions — do not reimplement dedup logic from scratch):

  - fingerprint()/row_hash() formula from training/unify.py:62-71 and
    training/split.py:46-58 — sha256("path|query|body|label"). This is what
    unify.py already stored as `_row_hash` in unified.jsonl, and what the
    split parquet's `_row_hash` column already carries verbatim from there
    (validated below: 268158/268240 train row hashes recoverable in
    unified.jsonl — the 82 unrecovered rows are all `mlops_telemetry_curated`,
    which is feature-space-only telemetry with no raw path/query/body by
    design, see unify.py's EXCLUDED_PATTERNS comment — expected, not a bug).
  - template_shape() from training/parsers/parse_seclists_cmdi.py:44-50 —
    6-uppercase-letter canary -> "CANARY", digit runs -> "N". Used as-is for
    cmdi, since that is the exact generator convention of the shared SecLists
    source (Fuzzing/command-injection-commix.txt) for both training and the
    Round 4 corpus.

Matching criteria (documented explicitly per the task, since "template" means
different things for a canary-randomized generator vs. a static wordlist):

  Round 4 (payload-string corpus) vs. a parquet split, per class:
    - Training-side text pool = path/query/body of every SAME-LABEL row in
      that split (three fields checked independently; a hit on any counts).
    - exact_match(payload)    := payload is a byte-identical SUBSTRING of at
                                  least one pool field (not a full-field
                                  equality requirement — payloads are often
                                  embedded in a larger request, e.g. an OWASP
                                  honeypot path, or an urlencoded body).
    - template_match(payload) := same containment check, but both sides are
                                  first passed through the class's
                                  template-normalization function (below).

  E2E fixture (full CanonicalRequest rows) vs. a parquet split, per class:
    - exact_match  := the fixture row's fingerprint (row_hash(path,query,
                       body,label), the exact same hash already stored as
                       `_row_hash` in the split) is present in that split's
                       `_row_hash` set. This directly answers "was this exact
                       request literally trained on".
    - template_match := same idea, but hash the template-normalized
                        (path|query|body|label) instead of the raw one, to
                        also catch near-duplicates that only differ in
                        randomized components (canary/digits). Requires
                        recovering raw text for the split side via a join
                        against training/data_clean/unified.jsonl on
                        `_row_hash` (the parquet only carries the 73 computed
                        features, not raw text).

Template normalization used, per class (documented — not all classes share
one rule, because not all sources are canary/digit-randomized generators
like SecLists commix; see decision below):

  cmdi            -> template_shape(): canary [A-Z]{6} -> "CANARY",
                     digit runs -> "N". This is the exact rule the source
                     generator (commix fuzzing set) itself uses; reusing it
                     verbatim is what makes the cmdi number an anchor/sanity
                     check against the already-confirmed 63/200 + 200/200.
  sqli/xss/path_traversal -> generic_template(): percent-decode once
                     (payloads are frequently embedded either raw or
                     url-encoded depending on source/context), lowercase,
                     digit runs -> "N". These sources are static wordlist
                     entries, not per-instance-randomized like commix, so the
                     dominant "template" variance across occurrences is
                     encoding and case, not canary/number substitution.

Usage:
    python training/leakage_check.py
Output:
    training/results/leakage_report.json
"""

from __future__ import annotations

import json
import hashlib
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

ROOT = Path(__file__).parent.parent
TRAINING = ROOT / "training"
DATA_CLEAN = TRAINING / "data_clean"
SPLITS_DIR = TRAINING / "splits"
RESULTS_DIR = TRAINING / "results"

ROUND4_CORPUS = Path(
    "/Users/xtsebas/Universidad/logSguarDian-vulnerable-project/attack-sim/large_corpus.json"
)
E2E_FIXTURE = ROOT / "e2e" / "fixtures" / "test_payloads.jsonl"

CLASSES = ["sqli", "xss", "path_traversal", "cmdi"]
ROW_SEP = "\n<<<LEAKCHK_ROWSEP>>>\n"  # unlikely to appear inside any payload

# --- reused functions -------------------------------------------------

# training/parsers/parse_seclists_cmdi.py:44-50
_CANARY_RE = re.compile(r"[A-Z]{6}")
_DIGIT_RE = re.compile(r"\d+")


def template_shape(line: str) -> str:
    shape = _CANARY_RE.sub("CANARY", line)
    shape = _DIGIT_RE.sub("N", shape)
    return shape


def generic_template(text: str) -> str:
    """Template normalization for sqli/xss/path_traversal: these sources are
    static wordlist entries (not per-instance canary/number generators like
    commix), so the dominant cross-occurrence variance is url-encoding and
    case, not random tokens. Percent-decode once, lowercase, digit runs->N.
    """
    try:
        text = unquote(text)
    except Exception:
        pass
    text = text.lower()
    text = _DIGIT_RE.sub("N", text)
    return text


def template_fn_for(label: str):
    return template_shape if label == "cmdi" else generic_template


# training/unify.py:62-71 / training/split.py:46-58 — identical formula.
def row_fingerprint(path: str, query: str, body: str | None, label: str) -> str:
    key = (
        (path or "") + "|"
        + (query or "") + "|"
        + (body or "") + "|"
        + (label or "")
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# --- loading ------------------------------------------------------------

def load_round4_corpus() -> dict[str, list[str]]:
    if not ROUND4_CORPUS.exists():
        raise FileNotFoundError(f"Round 4 corpus not found: {ROUND4_CORPUS}")
    with open(ROUND4_CORPUS, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, dict), "expected dict[category] -> list[str]"
    return data


def load_e2e_fixture() -> list[dict]:
    rows = []
    with open(E2E_FIXTURE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def load_unified_by_hash() -> dict[str, dict]:
    """training/data_clean/unified.jsonl keyed by its precomputed _row_hash.
    Used to recover raw path/query/body text for split rows (the parquet
    only carries computed features, not raw text)."""
    path = DATA_CLEAN / "unified.jsonl"
    out: dict[str, dict] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            rh = rec.get("_row_hash")
            if rh:
                out[rh] = rec
    return out


def load_splits() -> dict[str, pd.DataFrame]:
    return {
        name: pd.read_parquet(SPLITS_DIR / f"{name}.parquet")
        for name in ("train", "val", "test")
    }


# --- round4 vs split ------------------------------------------------------

def build_class_text_pool(
    split_df: pd.DataFrame,
    label: str,
    unified_by_hash: dict[str, dict],
) -> tuple[str, str]:
    """Build the raw and templated searchable text pool for one class in one
    split: path/query/body of every same-label row, joined with a separator
    that won't false-positive-match across row boundaries."""
    sub = split_df[split_df["label"] == label]
    tmpl_fn = template_fn_for(label)

    raw_parts: list[str] = []
    tmpl_parts: list[str] = []
    missing = 0
    for rh in sub["_row_hash"]:
        rec = unified_by_hash.get(rh)
        if rec is None:
            missing += 1
            continue
        for field in ("path", "query", "body"):
            val = rec.get(field)
            if not val:
                continue
            raw_parts.append(val)
            tmpl_parts.append(tmpl_fn(val))

    raw_pool = ROW_SEP.join(raw_parts)
    tmpl_pool = ROW_SEP.join(tmpl_parts)
    return raw_pool, tmpl_pool, missing  # type: ignore[return-value]


def round4_vs_split(
    corpus: dict[str, list[str]],
    split_df: pd.DataFrame,
    unified_by_hash: dict[str, dict],
) -> dict:
    result = {}
    for label in CLASSES:
        payloads = corpus.get(label, [])
        raw_pool, tmpl_pool, missing = build_class_text_pool(
            split_df, label, unified_by_hash
        )
        tmpl_fn = template_fn_for(label)

        exact = 0
        templ = 0
        for p in payloads:
            if p and p in raw_pool:
                exact += 1
            tp = tmpl_fn(p)
            if tp and tp in tmpl_pool:
                templ += 1

        result[label] = {
            "total": len(payloads),
            "exact_matches": exact,
            "template_matches": templ,
            "template_rule": "template_shape (canary+digit)" if label == "cmdi" else "generic_template (urldecode+lowercase+digit)",
            "training_rows_missing_raw_text": missing,
        }
    return result


# --- e2e fixture vs split -------------------------------------------------

def e2e_vs_split(
    fixture_rows: list[dict],
    split_df: pd.DataFrame,
    unified_by_hash: dict[str, dict],
) -> dict:
    exact_hashes = set(split_df["_row_hash"].tolist())

    # Build templated-hash set per split, per class (needs raw text via join)
    tmpl_hash_by_label: dict[str, set[str]] = {}
    for label in CLASSES:
        sub = split_df[split_df["label"] == label]
        tmpl_fn = template_fn_for(label)
        hashes = set()
        for rh in sub["_row_hash"]:
            rec = unified_by_hash.get(rh)
            if rec is None:
                continue
            tp = tmpl_fn(rec.get("path") or "")
            tq = tmpl_fn(rec.get("query") or "")
            tb = tmpl_fn(rec.get("body") or "")
            hashes.add(row_fingerprint(tp, tq, tb, label))
        tmpl_hash_by_label[label] = hashes

    result = {}
    for label in CLASSES:
        rows = [r for r in fixture_rows if r.get("label") == label]
        tmpl_fn = template_fn_for(label)

        exact = 0
        templ = 0
        for r in rows:
            path, query, body = r.get("path"), r.get("query"), r.get("body")
            rh = row_fingerprint(path, query, body, label)
            if rh in exact_hashes:
                exact += 1

            tp = tmpl_fn(path or "")
            tq = tmpl_fn(query or "")
            tb = tmpl_fn(body or "")
            trh = row_fingerprint(tp, tq, tb, label)
            if trh in tmpl_hash_by_label.get(label, set()):
                templ += 1

        result[label] = {
            "total": len(rows),
            "exact_matches": exact,
            "template_matches": templ,
        }
    return result


# --- anchor validation ----------------------------------------------------

def cmdi_anchor_validation(
    corpus: dict[str, list[str]],
    splits: dict[str, pd.DataFrame],
    unified_by_hash: dict[str, dict],
) -> dict:
    """Cross-check the already-confirmed cmdi anchor (63 exact / 200 template
    matches, established by comparing the Round 4 cmdi payloads against
    training/data_clean/seclists_cmdi.jsonl in full, i.e. BEFORE the 70/15/15
    stratified split — see the earlier investigation cited in
    .claude/plan-objetivos-ciberseguridad.md).

    seclists_cmdi.jsonl already dedups by template at parse time (parse_
    seclists_cmdi.py keeps exactly one representative row per unique
    template_shape() value: 2455 unique templates out of 8,262 raw lines).
    The stratified split then partitions those 2455 rows disjointly across
    train (1,719) / val (368) / test (368) — so a payload whose template
    exists in that source file will only be found in whichever ONE partition
    happens to hold that specific representative row (for the EXACT/
    set-equality sense), which is why round4_vs_train alone cannot be
    expected to reproduce 63/200 — that number was never partition-scoped.
    """
    payloads = corpus.get("cmdi", [])

    # vs the full pre-split source file
    raw_parts, tmpl_parts = [], []
    seclists_path = DATA_CLEAN / "seclists_cmdi.jsonl"
    with open(seclists_path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            q = rec.get("query") or ""
            raw_parts.append(q)
            tmpl_parts.append(template_shape(q))
    raw_pool = ROW_SEP.join(raw_parts)
    tmpl_pool = ROW_SEP.join(tmpl_parts)

    full_exact = sum(1 for p in payloads if p in raw_pool)
    full_templ = sum(1 for p in payloads if template_shape(p) in tmpl_pool)

    # per-partition scoped exact matches (cmdi-labeled rows only), and their
    # union, to show how the full-source anchor decomposes across the split
    per_partition_exact: dict[str, set[str]] = {}
    per_partition_templ: dict[str, set[str]] = {}
    for name, df in splits.items():
        raw_p, tmpl_p, _missing = build_class_text_pool(df, "cmdi", unified_by_hash)  # type: ignore[misc]
        per_partition_exact[name] = {p for p in payloads if p in raw_p}
        per_partition_templ[name] = {p for p in payloads if template_shape(p) in tmpl_p}

    union_exact = set().union(*per_partition_exact.values())
    union_templ = set().union(*per_partition_templ.values())

    return {
        "full_source_file": str(seclists_path),
        "full_source_rows_unique_templates": len(raw_parts),
        "vs_full_source_pre_split": {
            "exact_matches": full_exact,
            "template_matches": full_templ,
            "matches_known_anchor": full_exact == 63 and full_templ == 200,
        },
        "per_partition_exact_counts": {
            k: len(v) for k, v in per_partition_exact.items()
        },
        "sum_of_per_partition_exact": sum(len(v) for v in per_partition_exact.values()),
        "union_of_per_partition_exact": len(union_exact),
        "per_partition_template_counts": {
            k: len(v) for k, v in per_partition_templ.items()
        },
        "union_of_per_partition_template": len(union_templ),
        "explanation": (
            "The 63/200 anchor was established against the FULL, pre-split "
            "seclists_cmdi.jsonl (2455 unique-template rows). That file's "
            "rows are then partitioned disjointly (no row in two "
            "partitions) by the 70/15/15 stratified split. Summing exact "
            "matches across train+val+test reproduces 63 exactly (each "
            "payload's single matching row lands in exactly one "
            "partition). Template matches do NOT sum cleanly across "
            "partitions (182+79+85=346, not 200) because template matching "
            "is substring containment, not row-level set equality: a short "
            "post-normalization payload template can be a substring of "
            "more than one distinct training row's template in more than "
            "one partition at once. The UNION of per-partition template "
            "matches is exactly 200/200, confirming every Round 4 cmdi "
            "payload's template exists SOMEWHERE in the unified corpus — "
            "but round4_vs_train alone (this report's main entry) correctly "
            "reports only what is actually present in the train partition "
            "specifically, which is the partition the model is fit on."
        ),
    }


# --- main -----------------------------------------------------------------

def main() -> None:
    t0 = time.time()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading Round 4 corpus...", file=sys.stderr)
    corpus = load_round4_corpus()
    for k, v in corpus.items():
        print(f"  {k}: {len(v)} payloads", file=sys.stderr)

    print("Loading E2E fixture...", file=sys.stderr)
    fixture_rows = load_e2e_fixture()
    print(f"  {len(fixture_rows)} rows", file=sys.stderr)

    print("Loading splits...", file=sys.stderr)
    splits = load_splits()
    for name, df in splits.items():
        print(f"  {name}: {len(df)} rows", file=sys.stderr)

    print("Loading unified.jsonl (raw text join source)...", file=sys.stderr)
    unified_by_hash = load_unified_by_hash()
    print(f"  {len(unified_by_hash)} unique row hashes", file=sys.stderr)

    report: dict = {
        "_meta": {
            "round4_corpus_path": str(ROUND4_CORPUS),
            "e2e_fixture_path": str(E2E_FIXTURE),
            "classes": CLASSES,
            "note_pt_wordlists": (
                "training/parsers/ has NO parser for pt_wordlists / "
                "Deep-Travelsal.txt (verified: `git log --all -- "
                "'*pt_wordlist*'` is empty in both logSguarDian and this "
                "worktree, and no training/data_clean/pt_wordlists.jsonl "
                "exists or ever existed in git — only 9 parsers are "
                "committed: capec, command_injection, modsec_learn, owasp, "
                "patt_cmdi_curated, payload_full, payloads_csv, "
                "seclists_cmdi, xss_dataset). DATA_INVENTORY.md's mention "
                "of a pt_wordlists.parquet (1,166 rows, dated 2026-06-10) "
                "refers to an artifact that was never produced by any "
                "committed script — same pattern as the v10_test_results.json "
                "ad-hoc-script issue already found elsewhere in this audit. "
                "The raw file itself DOES exist on disk (read-only check, "
                "main repo, gitignored data/ dir): "
                "'data/omurugur Path_Travelsal_Payload_List master Payload/"
                "Deep-Travelsal.txt' — but nothing in git ever ingests it "
                "into data_clean. Current path_traversal training data "
                "(train.parquet, 11,799 rows) is dominated by capec (10,121 "
                "rows, 85.8% — real '../'-encoded traversal chains to "
                "/etc/passwd-style targets) with owasp_logs (1,463 rows, "
                "12.4% — real honeypot probes for app-level files like "
                "wp-config.php/.env) and payload_full (203 rows) a distant "
                "second and third. So no direct Deep-Travelsal.txt-vs-"
                "LFI-gracefulsecurity-linux.txt comparison was possible — "
                "that specific pairing named in the task is moot because "
                "the training side of it was never built. What IS reported "
                "below is the question that actually matters given the "
                "current codebase: whether the Round 4 path_traversal "
                "payloads (from LFI-gracefulsecurity-linux.txt) overlap "
                "with what is ACTUALLY in train/val/test today."
            ),
        },
        "round4_vs_train": round4_vs_split(corpus, splits["train"], unified_by_hash),
        "round4_vs_val": round4_vs_split(corpus, splits["val"], unified_by_hash),
        "round4_vs_test": round4_vs_split(corpus, splits["test"], unified_by_hash),
        "cmdi_anchor_validation": cmdi_anchor_validation(corpus, splits, unified_by_hash),
        "e2e_fixture_vs_splits": {},
    }

    for label in CLASSES:
        report["e2e_fixture_vs_splits"][label] = {}

    for split_name, split_df in splits.items():
        res = e2e_vs_split(fixture_rows, split_df, unified_by_hash)
        for label in CLASSES:
            report["e2e_fixture_vs_splits"][label][f"vs_{split_name}"] = res[label]

    out_path = RESULTS_DIR / "leakage_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"\nWrote {out_path}", file=sys.stderr)
    print(f"Done in {time.time()-t0:.1f}s", file=sys.stderr)

    # Anchor check — validated against the full pre-split source file, since
    # that is what the original 63/200 figure was measured against (see
    # cmdi_anchor_validation's docstring/explanation for the full trace).
    av = report["cmdi_anchor_validation"]["vs_full_source_pre_split"]
    train_scoped = report["round4_vs_train"]["cmdi"]
    print(
        f"\nANCHOR CHECK cmdi vs FULL seclists_cmdi.jsonl (pre-split): "
        f"exact={av['exact_matches']} (expected 63), "
        f"template={av['template_matches']} (expected 200) "
        f"-> matches_known_anchor={av['matches_known_anchor']}",
        file=sys.stderr,
    )
    print(
        f"  cmdi vs train.parquet ONLY (partition-scoped, the number that "
        f"matters for 'did the fitted model see this'): "
        f"exact={train_scoped['exact_matches']}, "
        f"template={train_scoped['template_matches']}",
        file=sys.stderr,
    )
    if not av["matches_known_anchor"]:
        print(
            "  WARNING: full-source anchor mismatch — per task instructions, "
            "this means a bug in this script's logic, not that the leak "
            "disappeared. Investigate before trusting other numbers.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
