#!/usr/bin/env python3
"""
Persona "dashboard": GET-heavy analytics/reporting UI traffic.
Date-range query params, report-export endpoints, moderate path depth,
session cookie present, real desktop/mobile browser UA pool.

Usage:
  python3 generate_dashboard.py --count 1000 --seed 42 --out ../data_clean/synthetic_dashboard_1000.jsonl
"""
import random
import sys

from common import base_arg_parser, build_record, make_nonce, write_jsonl, BROWSER_DESKTOP_UA, BROWSER_MOBILE_UA

SOURCE = "synthetic_dashboard"

REPORT_PATHS = [
    "/reports/sales/monthly",
    "/reports/sales/weekly",
    "/reports/sales/daily",
    "/reports/inventory/weekly",
    "/reports/inventory/monthly",
    "/reports/traffic/monthly",
    "/reports/conversion/weekly",
    "/reports/revenue/quarterly",
    "/reports/customers/monthly",
    "/reports/churn/monthly",
]

NAV_PATHS = [
    "/dashboard",
    "/dashboard/overview",
    "/dashboard/widgets",
    "/analytics",
    "/analytics/funnels",
    "/analytics/cohorts",
    "/analytics/segments",
    "/settings/dashboard",
    "/reports",
    "/reports/saved",
]

EXPORT_FORMATS = ["csv", "pdf", "xlsx"]
GRANULARITIES = ["day", "week", "month", "quarter"]

YEARS = [2025, 2026]


def random_date(rng: random.Random) -> str:
    year = rng.choice(YEARS)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def random_date_range(rng: random.Random) -> tuple:
    year = rng.choice(YEARS)
    start_month = rng.randint(1, 10)
    span = rng.randint(1, 3)
    from_date = f"{year:04d}-{start_month:02d}-01"
    end_month = min(start_month + span, 12)
    to_date = f"{year:04d}-{end_month:02d}-{rng.randint(20, 28):02d}"
    return from_date, to_date


def make_query(rng: random.Random, nonce: str) -> str:
    # "from"/"to" collide with the SQLi keyword regex (patterns.ts SQL_KEYWORDS_COUNT
    # matches "from\b" for UNION SELECT...FROM detection) - verified clear of every
    # class's keyword/marker regex via packages/extractor/dist/patterns.js.
    start_date, end_date = random_date_range(rng)
    parts = [f"start_date={start_date}", f"end_date={end_date}"]
    if rng.random() < 0.4:
        parts.append(f"granularity={rng.choice(GRANULARITIES)}")
    if rng.random() < 0.3:
        parts.append(f"format={rng.choice(EXPORT_FORMATS)}")
    if rng.random() < 0.2:
        parts.append(f"cache_bust={nonce[:8]}")
    return "&".join(parts)


def make_cookie(rng: random.Random, nonce: str) -> str:
    if rng.random() < 0.1:
        return ""
    return f"session_id={nonce}"


def generate_one(rng: random.Random, index: int) -> dict:
    nonce = make_nonce(rng)
    is_export = rng.random() < 0.35
    is_post = rng.random() < 0.15

    if is_export:
        path = rng.choice(REPORT_PATHS)
    else:
        path = rng.choice(NAV_PATHS)

    method = "POST" if is_post else "GET"
    query = make_query(rng, nonce) if (is_export or rng.random() < 0.6) else ""

    ua_pool = BROWSER_DESKTOP_UA if rng.random() < 0.75 else BROWSER_MOBILE_UA
    user_agent = rng.choice(ua_pool)

    body = ""
    content_type = ""
    if is_post:
        body = f"export_format={rng.choice(EXPORT_FORMATS)}&request_id={nonce}"
        content_type = "application/x-www-form-urlencoded"

    referer = "http://localhost:3000/dashboard" if rng.random() < 0.5 else ""
    cookie = make_cookie(rng, nonce)
    extra_headers = {}
    if rng.random() < 0.2:
        extra_headers["x-requested-with"] = "XMLHttpRequest"

    return build_record(
        method=method,
        path=path,
        query=query,
        user_agent=user_agent,
        content_type=content_type,
        referer=referer,
        cookie=cookie,
        extra_headers=extra_headers,
        body=body,
        source=SOURCE,
    )


def main():
    args = base_arg_parser(__doc__).parse_args()
    rng = random.Random(args.seed)
    records = [generate_one(rng, i) for i in range(args.count)]
    write_jsonl(records, args.out)
    print(f"wrote {len(records)} records -> {args.out}")


if __name__ == "__main__":
    main()
