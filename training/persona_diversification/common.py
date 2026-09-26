"""
Shared helpers for the persona-based benign-traffic generators
(dashboard, api_only, admin_panel). Same style as synthetic_nav_ecommerce's
generator: nonce-based uniqueness, persona-specific UA pool, output count
as a CLI parameter so each persona can be re-run at multiple scales without
editing the script. See docs/limitations.md §4 "Future work" for the
structural gap this addresses (99.6% of benign corpus has no real HTTP
request shape).
"""
import argparse
import json
import random
import string

BROWSER_DESKTOP_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

BROWSER_MOBILE_UA = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Samsung",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

API_CLIENT_UA = [
    "axios/1.6.7",
    "okhttp/4.12.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "curl/8.4.0",
    "PostmanRuntime/7.36.0",
    "node-fetch/3.3.2",
]

RECORD_FIELD_ORDER = [
    "method", "path", "query", "userAgent", "contentType",
    "referer", "cookie", "extraHeaders", "body", "label", "_source",
]


def make_nonce(rng: random.Random, length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def build_record(
    method: str,
    path: str,
    query: str,
    user_agent: str,
    content_type: str,
    referer: str,
    cookie: str,
    extra_headers: dict,
    body: str,
    source: str,
) -> dict:
    record = {
        "method": method,
        "path": path,
        "query": query,
        "userAgent": user_agent,
        "contentType": content_type,
        "referer": referer,
        "cookie": cookie,
        "extraHeaders": extra_headers,
        "body": body,
        "label": "benign",
        "_source": source,
    }
    return {k: record[k] for k in RECORD_FIELD_ORDER}


def write_jsonl(records, out_path: str) -> None:
    with open(out_path, "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def base_arg_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--count", type=int, required=True, help="number of records to generate")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default 42, deterministic)")
    p.add_argument("--out", type=str, required=True, help="output .jsonl path")
    return p
