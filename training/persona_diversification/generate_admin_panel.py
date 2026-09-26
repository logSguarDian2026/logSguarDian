#!/usr/bin/env python3
"""
Persona "admin-panel": privileged back-office UI traffic.
Deeper nested paths (/admin/users/:id/permissions), privileged session
markers, mix of GET/POST, moderate query use for filtering/pagination.
Desktop-heavy browser UA pool (admin panels are rarely used from mobile).

Usage:
  python3 generate_admin_panel.py --count 1000 --seed 42 --out ../data_clean/synthetic_admin_panel_1000.jsonl
"""
import random

from common import base_arg_parser, build_record, make_nonce, write_jsonl, BROWSER_DESKTOP_UA, BROWSER_MOBILE_UA

SOURCE = "synthetic_admin_panel"

USER_SUBPATHS = ["permissions", "roles", "sessions", "audit-log", "reset-password"]
SETTINGS_SUBPATHS = ["audit-log", "feature-flags", "rate-limits", "webhooks", "api-keys"]

NAV_PATHS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/roles",
    "/admin/settings",
    "/admin/settings/audit-log",
    "/admin/reports",
]

STATUS_FILTERS = ["active", "suspended", "pending", "deleted"]
SORT_FIELDS = ["created_at", "last_login", "email", "role"]


def random_id(rng: random.Random) -> str:
    return str(rng.randint(1, 50000))


def make_deep_path(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.45:
        return f"/admin/users/{random_id(rng)}/{rng.choice(USER_SUBPATHS)}"
    elif kind < 0.7:
        return f"/admin/settings/{rng.choice(SETTINGS_SUBPATHS)}"
    elif kind < 0.85:
        return f"/admin/roles/{random_id(rng)}"
    else:
        return rng.choice(NAV_PATHS)


def make_query(rng: random.Random) -> str:
    parts = []
    if rng.random() < 0.6:
        parts.append(f"page={rng.randint(1, 40)}")
        parts.append(f"limit={rng.choice([20, 50, 100])}")
    if rng.random() < 0.4:
        parts.append(f"status={rng.choice(STATUS_FILTERS)}")
    if rng.random() < 0.3:
        parts.append(f"sort={rng.choice(SORT_FIELDS)}")
    return "&".join(parts)


def make_privileged_cookie(rng: random.Random, nonce: str) -> str:
    session = f"admin_session={nonce}"
    if rng.random() < 0.5:
        session += f"; role=admin"
    return session


def generate_one(rng: random.Random, index: int) -> dict:
    nonce = make_nonce(rng)
    path = make_deep_path(rng)
    is_mutation = rng.random() < 0.3
    method = rng.choice(["POST", "PUT", "DELETE"]) if is_mutation else "GET"

    query = make_query(rng) if (not is_mutation and rng.random() < 0.7) else ""

    body = ""
    content_type = ""
    if is_mutation:
        body = f"action_id={nonce}&confirm=true"
        content_type = "application/x-www-form-urlencoded"

    ua_pool = BROWSER_DESKTOP_UA if rng.random() < 0.9 else BROWSER_MOBILE_UA
    user_agent = rng.choice(ua_pool)

    referer = "http://localhost:3000/admin" if rng.random() < 0.5 else ""
    cookie = make_privileged_cookie(rng, nonce)
    extra_headers = {}
    if rng.random() < 0.25:
        extra_headers["x-admin-role"] = "admin"

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
