# Scoping the extractor fix for the 3 confirmed collision mechanisms

Scoping only, per task — nothing implemented, no code changed, no
retrain run. Reuses the exact safety-check discipline from
`non_form_operator_count`'s original investigation (commit `2116c93`:
"preserving signal for the 12.53% of sqli corpus rows that depend on it
as their sole SQLi-specific feature - verified via corpus scan, not
assumed"), against `training/data_clean/features.csv` (the real
extracted corpus that trained `rf_v11`; 382,950 rows, `sqli` 227,344 /
`benign` 99,112 / `xss` 29,897 / `path_traversal` 16,839 / `cmdi` 9,758 —
matches `docs/limitations.md` §5.1's cited counts exactly, confirming
this is the right corpus snapshot). Script:
`training/persona_diversification/check_feature_safety.py`.

## STEP 1: corpus safety scan — all 3 features are safe to adjust

| Feature | Class | n | Sole-dependency n | Sole-dependency % |
|---|---|---:|---:|---:|
| `sqli_operator_count` | sqli | 227,344 | 23,942 | **10.53%** |
| `quote_count` | sqli | 227,344 | 191 | **0.084%** |
| `base64_like_count` | sqli | 227,344 | 769 | 0.34% |
| `base64_like_count` | xss | 29,897 | 122 | 0.41% |
| `base64_like_count` | path_traversal | 16,839 | 8 | 0.05% |
| `base64_like_count` | cmdi | 9,758 | 181 | 1.85% |

"Sole-dependency" = feature is nonzero and every other feature in that
attack class's own detection group is zero (same definition the
`non_form_operator_count` PR used).

**`sqli_operator_count` sits right at the precedent's own baseline**
(10.53% vs. the 12.53% the project already shipped an additive fix
against). **`quote_count` and `base64_like_count` are an order of
magnitude safer** than that already-accepted precedent (0.05-1.85% vs.
12.53%). None of these numbers are a reason to hesitate — they're
comfortably inside territory this project has already validated as
acceptable for an additive fix.

Bonus finding, worth flagging: `base64_like_count` is already extremely
noisy in the *existing* corpus, independent of any synthetic persona —
49.5% of all `sqli` rows and 38.2% of all `benign` rows have
`base64_like_count > 0`. It separates the two classes by only ~11
percentage points corpus-wide. A narrow fix to this feature is very
unlikely to cost real signal because the feature barely carries
separating signal today.

## STEP 2: designed adjustments (prototyped, not wired in)

### `base64_like_count` — regex bug, not a new feature

```
grep -n "BASE64" packages/extractor/src/patterns.ts
  export const BASE64_LIKE_COUNT = /[A-Za-z0-9+\/]{20,}={0,2}/g;
```

The regex's own character class includes `/` — a REST path with enough
alnum segments (`/api/v1/tokens/d7e805da`) forms an unbroken 20+ char
"base64-like" run purely from path separators, no UUID-specific carve-
out needed. This is also the more correct fix in general: real base64
embedded in a URL is virtually always base64url-encoded (`-`/`_`
instead of `+`/`/`) specifically *because* raw `/` in a URL is a path
separator — so treating literal `/` as a base64 character was already
questionable independent of this task's finding. Prototyped:

```js
OLD: /[A-Za-z0-9+\/]{20,}={0,2}/g
NEW: /[A-Za-z0-9+]{20,}={0,2}/g

"/api/v1/tokens/d7e805da-846a-32c3-bb81-e3c29b621792"
  OLD match: ["/api/v1/tokens/d7e805da"]   NEW match: null
"dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0ZW5jb2Rpbmc=" (real base64)
  OLD match: [full string]                 NEW match: [full string] (unchanged)
```

**A one-character regex edit, not a new feature.** No new column, no
`FEATURE_NAMES` change, no determinism-fixture dimension bump. Still
needs: parity-gate re-run (`gate_parity.py` — the regex is pure JS, no
Python counterpart in this repo to keep in sync, so no cross-language
parity risk here beyond the existing TS/onnxruntime-node check),
determinism golden fixture regen (values change, dimension doesn't),
and the TS unit tests that assert specific `base64_like_count` values
on fixed inputs (`packages/core/tests`, `packages/extractor` — need a
grep to find and update any hardcoded expectations, same as the
72→73 test updates `non_form_operator_count` required).

### `quote_count` — a `non_form_operator_count`-shaped additive feature

Mirrors the existing pattern exactly: a new regex counts quotes
immediately adjacent to JSON delimiters, then `max(0, quote_count -
json_kv_quote_count)` nets out structural JSON quoting the same way
`non_form_operator_count` nets out structural form-field `=`.
Prototyped and verified against both a JSON body and a real SQLi
quote-breakout payload:

```js
JSON_KV_QUOTE = /"(?=\s*[:,}\]])|(?<=[:,{\[]\s*)"/g

{"request_id": "x", "name": "y", "status": "z", "amount": 1}
  quote_count=14  json_kv_quotes=14  discounted=0   (fully netted - correct)

username=admin&password=hunter2
  quote_count=0   json_kv_quotes=0   discounted=0   (no-op on form data - correct)

username=' OR 1=1--&password=x
  quote_count=1   json_kv_quotes=0   discounted=1   (real attack signal preserved - correct)
```

Same shape of change as `non_form_operator_count`'s PR: one new regex
constant (`patterns.ts`), one new derived feature in `semantic.ts`,
`FEATURE_NAMES` 75→76, `EXCLUDED_NAMES`/DROP_COLS entry until a retrain
picks it up (additive-only, model input dimension unchanged until then
— same deferral the precedent used), determinism fixture regen, test
updates.

### `sqli_operator_count` in form/JSON bodies — **already fixed, not an extractor gap at all**

Re-checked whether this needs the "extend form-field logic to JSON
`key:value`" treatment the task proposed. It does not, for two
independent reasons:

1. JSON syntax contains no bare `=` character at all
   (`{"key": "value"}` uses `:`, not `=`) — `SQLI_OPERATOR_COUNT`'s
   regex only matches `=`, so JSON bodies structurally can't trigger it
   via this mechanism. (Confirmed directly: only 5% of `api_only`'s
   misclassified rows had `sqli_operator_count > 0` at all — consistent
   with only the ~30% of `api_only` requests that use `?page=1&limit=25`
   -style pagination query strings, not the JSON-body majority.)
2. **`non_form_operator_count` already exists in the codebase** (added
   in commit `2116c93`, July 2026) and **is already one of the 69
   features fed to `rf.onnx` today** (`training/notebooks/03_random_forest.ipynb`'s
   `DROP_COLS` does not drop it). Verified directly on the `admin_panel`
   misclassified rows:

   ```
   sqli_operator_count  non_form_operator_count
   2                    0
   2                    0
   3                    0
   4                    0
   ```

   The corrected, context-aware feature is present and correctly
   reads 0 for every one of these rows — the raw, uncorrected feature
   is what's still driving the `sqli` verdict. **This is not an
   extractor-code gap; it's a training/feature-weighting outcome** of
   an RF that has access to both the raw and the corrected signal and
   still leans on the raw one. No new code is needed here — only a
   retrain (optionally after also dropping raw `sqli_operator_count`
   from the training input alongside adding `non_form_operator_count`
   explicitly, or trusting a retrain with more diverse benign
   `key=value` shapes in the corpus to rebalance the split weight
   naturally) plus the same recall-regression check every other feature
   change here needs regardless.

## STEP 3: honest time estimate — **days, not weeks**

Nothing found in Steps 1-2 raises the risk profile above the
`non_form_operator_count` precedent that already shipped successfully;
if anything, two of the three mechanisms turned out cheaper than that
precedent:

| Mechanism | Nature of fix | Estimated effort |
|---|---|---|
| `base64_like_count` / UUID-path paths | 1-character regex edit | Hours (+ determinism fixture regen, test updates) |
| `quote_count` / JSON bodies | New additive feature, exact shape of an existing precedent | 0.5-1 day (mirrors a change this project has already made once) |
| `sqli_operator_count` / form bodies | No extractor code change — fix already exists in the codebase, unused by the current model | 0 extractor days; retrain-only |
| Retrain + parity/determinism/test updates for the above | Existing pipeline (`ct_pipeline.py`, notebooks 02-05, `gates/`) | 0.5-1 day of pipeline runtime + review |
| Recall-regression check (LOSO/dose-response, same discipline as §10) | Required before trusting the retrain — this is the one step that's genuinely investigative, not mechanical | 1-2 days |

**Total: roughly 3-5 working days** to get the extractor/model side to
where these three specific collisions no longer dominate the sanity
floor, comfortably before November. This is strictly the
extractor-and-retrain-validation track; it does not yet include
re-running the full persona-diversification LOSO mini-pipeline
integration test from the original task (that remains its own,
separately-scoped step, gated on this one landing clean) — but nothing
here suggests that follow-on has gotten any harder either.

**Nothing in this scoping pass found a reason to treat this as a
multi-week feature-engineering research problem.** The one open
question that *is* genuinely investigative rather than mechanical is
the recall-regression check — same category of work as §10's dose-response
sweep — and that was already going to be required no matter how simple
or complex the fixes themselves turned out to be.

## Not done in this pass (by design — scoping only)

No code changed in `packages/extractor/`, no `FEATURE_NAMES` bump, no
determinism fixture touched, no retrain run, no LOSO run. The three
prototypes above ran as standalone `node -e` snippets against the
compiled regex logic, not against the actual source files.
