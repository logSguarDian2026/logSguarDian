#!/usr/bin/env python3
"""
Automated safety check (STEP 3): three-way -> four-way MinHash overlap of
each persona/scale synthetic file against all 4 attack classes
(path_traversal, sqli, xss, cmdi) in unified.jsonl. Same methodology as
synthetic_nav_ecommerce's check (docs/limitations.md §4): datasketch
MinHash+LSH, k=3 char shingles, threshold=0.70, length-filtered
(<15 chars excluded as unreliable k=3 Jaccard estimates).

Each attack class is subsampled to MAX_CORPUS_PER_CLASS rows (seeded) for
tractability, matching the precedent in docs/limitations.md §5.1 of using
a bounded subset when full-corpus scanning is not the point of the check
(this is a synthetic-vs-corpus safety screen, not the exhaustive
near-duplicate audit that investigation performed).

The "raw text" compared is a simplified stand-in for the extractor's
deriveRawPayload: body if non-empty, else query, else path. This is an
approximation of the real TS field-priority/scoring logic
(packages/extractor/src/index.ts deriveRawPayload) sufficient for a
diagnostic overlap screen, not a byte-exact reproduction.

Flags (does not auto-reject) any cell with overlap > FLAG_THRESHOLD for
manual inspection.

Usage:
  python3 check_overlap.py > ../results/persona_overlap_report.json
"""
import json
import random
import sys
from pathlib import Path

from datasketch import MinHash, MinHashLSH

REPO = Path(__file__).resolve().parents[2]
UNIFIED = REPO / "training" / "data_clean" / "unified.jsonl"
DATA_CLEAN = REPO / "training" / "data_clean"

ATTACK_CLASSES = ["path_traversal", "sqli", "xss", "cmdi"]
PERSONAS = ["dashboard", "api_only", "admin_panel"]
SCALES = [200, 500, 1000, 2000]

MAX_CORPUS_PER_CLASS = 50_000
MIN_TEXT_LEN = 15
SHINGLE_K = 3
NUM_PERM = 64
LSH_THRESHOLD = 0.70
FLAG_THRESHOLD = 0.01
SAMPLE_SEED = 42


def raw_text(rec: dict) -> str:
    body = rec.get("body") or ""
    if body:
        return body
    query = rec.get("query") or ""
    if query:
        return query
    return rec.get("path") or ""


def shingles(text: str, k: int = SHINGLE_K):
    if len(text) < k:
        return {text}
    return {text[i:i + k] for i in range(len(text) - k + 1)}


def make_minhash(text: str) -> MinHash:
    m = MinHash(num_perm=NUM_PERM)
    for sh in shingles(text):
        m.update(sh.encode("utf8"))
    return m


def load_attack_corpora():
    print("loading unified.jsonl and splitting by label...", file=sys.stderr)
    buckets = {c: [] for c in ATTACK_CLASSES}
    with open(UNIFIED) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = rec.get("label")
            if label in buckets:
                text = raw_text(rec)
                if len(text) >= MIN_TEXT_LEN:
                    buckets[label].append(text)
    rng = random.Random(SAMPLE_SEED)
    for c in ATTACK_CLASSES:
        n = len(buckets[c])
        if n > MAX_CORPUS_PER_CLASS:
            buckets[c] = rng.sample(buckets[c], MAX_CORPUS_PER_CLASS)
        print(f"  {c}: corpus size used = {len(buckets[c])} (of {n} eligible rows)", file=sys.stderr)
    return buckets


def build_lsh_indexes(buckets):
    indexes = {}
    for c in ATTACK_CLASSES:
        print(f"building LSH index for {c}...", file=sys.stderr)
        lsh = MinHashLSH(threshold=LSH_THRESHOLD, num_perm=NUM_PERM)
        for i, text in enumerate(buckets[c]):
            lsh.insert(f"{c}_{i}", make_minhash(text))
        indexes[c] = lsh
    return indexes


def check_file(path: Path, indexes: dict) -> dict:
    total = 0
    evaluated = 0
    matches = {c: 0 for c in ATTACK_CLASSES}
    match_examples = {c: None for c in ATTACK_CLASSES}
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            total += 1
            text = raw_text(rec)
            if len(text) < MIN_TEXT_LEN:
                continue
            evaluated += 1
            mh = make_minhash(text)
            for c in ATTACK_CLASSES:
                result = indexes[c].query(mh)
                if result:
                    matches[c] += 1
                    if match_examples[c] is None:
                        match_examples[c] = text[:120]
    overlap_pct = {
        c: (matches[c] / evaluated if evaluated else 0.0)
        for c in ATTACK_CLASSES
    }
    return {
        "total_records": total,
        "evaluated_records": evaluated,
        "excluded_short_text": total - evaluated,
        "overlap_pct": overlap_pct,
        "match_examples": match_examples,
    }


def main():
    buckets = load_attack_corpora()
    indexes = build_lsh_indexes(buckets)

    report = {"config": {
        "max_corpus_per_class": MAX_CORPUS_PER_CLASS,
        "min_text_len": MIN_TEXT_LEN,
        "shingle_k": SHINGLE_K,
        "num_perm": NUM_PERM,
        "lsh_threshold": LSH_THRESHOLD,
        "flag_threshold": FLAG_THRESHOLD,
    }, "results": {}}

    for persona in PERSONAS:
        for scale in SCALES:
            fname = f"synthetic_{persona}_{scale}.jsonl"
            fpath = DATA_CLEAN / fname
            if not fpath.exists():
                print(f"MISSING: {fpath}", file=sys.stderr)
                continue
            print(f"checking {fname}...", file=sys.stderr)
            result = check_file(fpath, indexes)
            key = f"{persona}_{scale}"
            report["results"][key] = result
            max_overlap = max(result["overlap_pct"].values())
            flag = max_overlap > FLAG_THRESHOLD
            print(
                f"  {key}: max_overlap={max_overlap:.4%} "
                f"{'** FLAGGED **' if flag else ''}",
                file=sys.stderr,
            )

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
