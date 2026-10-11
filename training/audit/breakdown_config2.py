"""
Breakdown of config2 detection results for path_traversal and cmdi payloads.

Static analysis only: reads the attack corpus and the per-payload results
produced by the config2 run, classifies each payload with deterministic rules,
and writes per-group block rates with Wilson 95% intervals.

Usage:
    python breakdown_config2.py --corpus large_corpus_requests.json \
        --results results_config2.json --out breakdown_config2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import unquote

WILSON_Z_95 = 1.959963984540054
PERCENT = 100
DECIMALS = 2
HASH_CHUNK_BYTES = 1 << 20

PATH_TRAVERSAL = "path_traversal"
CMDI = "cmdi"
NO_SEPARATOR = "no_separator"
POSIX = "posix"
WINDOWS = "windows"

PATH_TRAVERSAL_RULES: list[tuple[str, Callable[[str], bool]]] = [
    ("null_byte", lambda p: "%00" in p.lower() or "\x00" in p),
    ("double_encoding", lambda p: re.search(r"%252[ef]", p, re.IGNORECASE) is not None),
    ("overlong_utf8", lambda p: re.search(r"%c0%a[ef]", p, re.IGNORECASE) is not None),
    ("dot_slash_duplication", lambda p: "....//" in p),
    ("backslash", lambda p: "\\" in p),
    ("absolute", lambda p: p.startswith("/")),
    ("encoded_dotdot_slash_or_mixed", lambda p: re.search(r"%2e%2e(%2f|/)", p, re.IGNORECASE) is not None),
    ("raw_dotdot_slash", lambda p: "../" in p),
]

WINDOWS_COMMAND_PATTERNS = [
    r"\btype C:\\",
    r"\bdir\b",
    r"\bnet user\b",
    r"\bpowershell\b",
    r"\bcmd /c\b",
    r"\bipconfig\b",
    r"\bsysteminfo\b",
    r"\btasklist\b",
]

SEPARATOR_PATTERN = re.compile(r"\|\||&&|[|&;\n`]|\$\(")
SEPARATOR_LABELS = {
    "||": "||",
    "&&": "&&",
    "|": "|",
    "&": "&",
    ";": ";",
    "\n": "newline (\\n / %0a)",
    "`": "backticks",
    "$(": "$()",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_fully(payload: str) -> str:
    decoded = payload
    while (next_value := unquote(decoded)) != decoded:
        decoded = next_value
    return decoded


def classify_path_traversal(payload: str) -> Optional[str]:
    for label, matches in PATH_TRAVERSAL_RULES:
        if matches(payload):
            return label
    return None


def classify_system(payload: str) -> str:
    decoded = decode_fully(payload)
    if any(re.search(pattern, decoded) for pattern in WINDOWS_COMMAND_PATTERNS):
        return WINDOWS
    return POSIX


def classify_separator(payload: str) -> str:
    match = SEPARATOR_PATTERN.search(decode_fully(payload))
    if match is None:
        return NO_SEPARATOR
    return SEPARATOR_LABELS[match.group()]


def wilson_interval_pct(successes: int, total: int) -> Optional[list[float]]:
    if total == 0:
        return None
    proportion = successes / total
    z_squared = WILSON_Z_95**2
    denominator = 1 + z_squared / total
    centre = (proportion + z_squared / (2 * total)) / denominator
    half_width = (
        WILSON_Z_95
        * math.sqrt(proportion * (1 - proportion) / total + z_squared / (4 * total * total))
        / denominator
    )
    return [
        round(PERCENT * (centre - half_width), DECIMALS),
        round(PERCENT * (centre + half_width), DECIMALS),
    ]


def summarize(records: list[dict]) -> dict:
    total = len(records)
    blocked = sum(1 for record in records if record["blocked"])
    return {
        "n": total,
        "blocked": blocked,
        "pct_blocked": round(PERCENT * blocked / total, DECIMALS) if total else None,
        "wilson_95_pct": wilson_interval_pct(blocked, total),
    }


def not_blocked_entries(records: list[dict]) -> list[dict]:
    return [
        {"id": record["id"], "payload": record["payload"], "status": record["status"]}
        for record in records
        if not record["blocked"]
    ]


def split_evaluated(records: list[dict]) -> tuple[list[dict], list[dict]]:
    evaluated = [record for record in records if record["blocked"] is not None]
    errors = [
        {"id": record["id"], "payload": record["payload"], "error": record["error"]}
        for record in records
        if record["blocked"] is None
    ]
    return evaluated, errors


def group_by_label(
    records: list[dict],
    labels: list[str],
    classify: Callable[[str], Optional[str]],
) -> tuple[dict[str, list[dict]], list[dict]]:
    groups: dict[str, list[dict]] = {label: [] for label in labels}
    unmatched: list[dict] = []
    for record in records:
        label = classify(record["payload"])
        if label is None:
            unmatched.append(record)
        else:
            groups[label].append(record)
    return groups, unmatched


def path_traversal_section(records: list[dict]) -> dict:
    evaluated, errors = split_evaluated(records)
    labels = [label for label, _ in PATH_TRAVERSAL_RULES]
    groups, unclassified = group_by_label(evaluated, labels, classify_path_traversal)
    return {
        **summarize(evaluated),
        "errors": errors,
        "by_encoding": {
            label: {**summarize(items), "not_blocked": not_blocked_entries(items)}
            for label, items in groups.items()
        },
        "unclassified": [
            {"id": record["id"], "payload": record["payload"], "status": record["status"]}
            for record in unclassified
        ],
    }


def cmdi_section(records: list[dict]) -> dict:
    evaluated, errors = split_evaluated(records)
    system_groups, _ = group_by_label(evaluated, [WINDOWS, POSIX], classify_system)
    separator_labels = [*dict.fromkeys(SEPARATOR_LABELS.values()), NO_SEPARATOR]
    separator_groups, _ = group_by_label(evaluated, separator_labels, classify_separator)
    return {
        **summarize(evaluated),
        "errors": errors,
        "by_system": {label: summarize(items) for label, items in system_groups.items()},
        "by_separator": {label: summarize(items) for label, items in separator_groups.items()},
        "not_blocked": not_blocked_entries(evaluated),
    }


def build_records(corpus: list[dict], results_by_id: dict[str, dict]) -> list[dict]:
    records = []
    for request in corpus:
        if request["category"] not in (PATH_TRAVERSAL, CMDI):
            continue
        result = results_by_id[request["id"]]
        records.append(
            {
                "id": request["id"],
                "category": request["category"],
                "payload": request["payload"],
                "status": result["status"],
                "blocked": result["blocked"],
                "error": result.get("error"),
            }
        )
    return records


def load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_report(corpus_path: Path, results_path: Path) -> dict:
    corpus = load_json(corpus_path)
    results_by_id = {result["id"]: result for result in load_json(results_path)}
    records = build_records(corpus, results_by_id)
    return {
        "inputs": {
            "corpus": {"path": str(corpus_path), "sha256": sha256_file(corpus_path)},
            "results": {"path": str(results_path), "sha256": sha256_file(results_path)},
        },
        PATH_TRAVERSAL: path_traversal_section(
            [record for record in records if record["category"] == PATH_TRAVERSAL]
        ),
        CMDI: cmdi_section([record for record in records if record["category"] == CMDI]),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True, help="large_corpus_requests.json")
    parser.add_argument("--results", type=Path, required=True, help="results_configX.json")
    parser.add_argument("--out", type=Path, required=True, help="output JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_report(args.corpus, args.results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
