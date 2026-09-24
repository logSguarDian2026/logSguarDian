#!/usr/bin/env python3
"""
Persona "api-only": pure REST API traffic, no browser ever hits it.
Mix of GET/POST/PUT/DELETE, JSON bodies (not urlencoded), Authorization:
Bearer headers instead of session cookies, non-browser client UA pool
(axios/okhttp/python-requests/Go-http-client/curl/Postman),
/api/v1/resources/:id path shape.

Usage:
  python3 generate_api_only.py --count 1000 --seed 42 --out ../data_clean/synthetic_api_only_1000.jsonl
"""
import json
import random

from common import base_arg_parser, build_record, make_nonce, write_jsonl, API_CLIENT_UA

SOURCE = "synthetic_api_only"

RESOURCES = [
    "users", "orders", "products", "invoices", "sessions",
    "webhooks", "payments", "subscriptions", "notifications", "tokens",
]

METHODS_WEIGHTED = ["GET"] * 5 + ["POST"] * 3 + ["PUT"] * 2 + ["DELETE"] * 1


def random_id(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return str(rng.randint(1000, 999999))
    hexch = "0123456789abcdef"
    return "-".join(
        "".join(rng.choice(hexch) for _ in range(n))
        for n in (8, 4, 4, 4, 12)
    )


def make_json_body(rng: random.Random, resource: str, nonce: str) -> str:
    fields = {
        "request_id": nonce,
        "name": f"{resource}_{rng.randint(1, 9999)}",
        "status": rng.choice(["active", "pending", "archived"]),
        "amount": round(rng.uniform(1.0, 500.0), 2),
    }
    if rng.random() < 0.3:
        fields["metadata"] = {"source": "api", "version": rng.choice(["v1", "v2"])}
    return json.dumps(fields)


def make_auth_header(rng: random.Random, nonce: str) -> str:
    token = nonce + make_nonce(rng, length=24)
    return f"Bearer {token}"


def generate_one(rng: random.Random, index: int) -> dict:
    nonce = make_nonce(rng)
    resource = rng.choice(RESOURCES)
    method = rng.choice(METHODS_WEIGHTED)

    needs_id = method in ("GET", "PUT", "DELETE") and rng.random() < 0.7
    path = f"/api/v1/{resource}"
    if needs_id:
        path = f"{path}/{random_id(rng)}"

    query = ""
    if method == "GET" and not needs_id and rng.random() < 0.6:
        page = rng.randint(1, 20)
        limit = rng.choice([10, 25, 50, 100])
        query = f"page={page}&limit={limit}"
        if rng.random() < 0.3:
            query += f"&status={rng.choice(['active', 'pending', 'archived'])}"

    body = ""
    content_type = ""
    if method in ("POST", "PUT"):
        body = make_json_body(rng, resource, nonce)
        content_type = "application/json"

    # Real API clients do send a UA - it's just never browser-shaped.
    user_agent = rng.choice(API_CLIENT_UA)

    extra_headers = {
        "authorization": make_auth_header(rng, nonce),
        "accept": "application/json",
    }
    if rng.random() < 0.15:
        extra_headers["x-request-id"] = nonce

    return build_record(
        method=method,
        path=path,
        query=query,
        user_agent=user_agent,
        content_type=content_type,
        referer="",
        cookie="",
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
