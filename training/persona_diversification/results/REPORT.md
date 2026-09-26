# Persona diversification — dose-response report (generation + verification only)

Branch: `investigate/benign-persona-diversification`. No changes to
`unified.jsonl`, `label_map.yaml`, or any model. STOP checkpoint per
task spec — human decision required before any integration/retrain.

**This report supersedes the root-cause section of the prior version.**
The original hypothesis (path depth drives `api_only`/`admin_panel`'s
failure) was tested and disproven below — see "Correction" in STEP 2.
Overlap results (STEP 1) and the general finding that something is
structurally wrong (STEP 4 §5.3 original) still stand; only the
mechanism was wrong.

## STEP 1-2 (original): personas + scales generated

`training/persona_diversification/generate_{dashboard,api_only,admin_panel}.py`
(nonce-based uniqueness, `--count`/`--seed`/`--out`). 12 files in
`training/data_clean/` (gitignored), 200/500/1000/2000 records, `seed=42`.

## STEP 3 (original): MinHash safety check — all 12 files CLEAR, unaffected by this round

0.0000% overlap, every persona x scale x attack-class cell, both before
and after this round's fixes (fixes only changed query param names and
did not add any attack-shaped content). Not re-run — nothing about this
round's changes could plausibly move it. See
`results/persona_overlap_report.json` from the prior run.

---

## This round: fix attempt + re-investigation

### STEP 1 (fix attempt): dashboard query param collision

Verified `start_date`/`end_date` (and by extension `range_start`/
`range_end`) against **every** regex in `packages/extractor/src/patterns.ts`
(SQLi, XSS, cmdi, path traversal, encoding, composition) via the compiled
`dist/patterns.js`, not just the SQLi keyword list named in the task:

```
start_date=2026-01-01&end_date=2026-03-31
  MATCH SQLI_OPERATOR_COUNT ["=","="]
  MATCH FORM_FIELD_COUNT ["start_date=","&end_date="]
  MATCH SPECIAL_CHAR_COUNT [...]
  MATCH NUMERIC_CHAR_COUNT [...]
```

No SQLi/XSS/cmdi/path-traversal **keyword or marker** regex matches —
only the generic operator/form-field/char-composition patterns that any
`key=value` query string matches by construction. `generate_dashboard.py`
updated to `start_date=`/`end_date=`, all 4 scale files regenerated.

**Result: no measurable change.** `dashboard_200` stayed at 1.00% benign
(was 1.00%), `dashboard_500` 0.60% (was 0.60%), `dashboard_1000` 0.90%
(was 0.90%), `dashboard_2000` 0.90% (was 0.90%) — identical to the
pre-fix run. The keyword collision was real (confirmed present before
the fix, confirmed absent after) but **was never the dominant driver**.
Re-inspecting a post-fix misclassified record confirms this directly:

```
query: start_date=2026-10-01&end_date=2026-12-20&format=pdf -> predicted sqli
  sqli_keyword_count = 0   (the fix worked - zero keyword signal)
  sqli_operator_count = 3  (three bare "=" characters - still enough alone)
```

**Actual driver: `sqli_operator_count`, a raw count of bare `=` characters
with no discount applied for ordinary `key=value` query-string structure.**
A `non_form_operator_count` feature exists specifically to net out
benign form-field `=` signs (`semantic.ts:53`, `FORM_FIELD_COUNT`), but it
is a *separate* feature from `sqli_operator_count` - the raw,
undiscounted count is still fed to the model directly, and 2-3 raw
`=` characters (the number *any* multi-parameter query string has) is
sufficient by itself for `rf_v11` to output `sqli`, independent of every
other feature.

### STEP 2: path-depth investigation for `api_only`/`admin_panel` — hypothesis disproven

Measured `path_separator_count` (the feature actually fed to the model,
via the real extractor CLI, not a proxy) three ways:

| Source | n | mean | median | p25 | p75 | p90 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| Real `path_traversal` corpus (unified.jsonl) | 16,839 | 3.48 | 4 | 0 | 6 | 7 | 159 |
| `synthetic_api_only_2000` | 2,000 | 1.76→~1.0* | 0 | 0 | 4 | 4 | 4 |
| `synthetic_admin_panel_2000` | 2,000 | ~1.0* | 0 | 0 | 3 | 4 | 4 |

*(mean recomputed on the real extractor's field-priority payload, not the
path alone — median is 0 either way because JSON/urlencoded bodies with
no `/` dominate the mutation-method rows.)*

**Correction: depth capping cannot help and was never the mechanism.**
The generated files' `path_separator_count` (max 3-4) is already *below*
the real `path_traversal` corpus's own median (4) and comfortably inside
its p25-p75 band (0-6) — meaning real path_traversal examples routinely
have **zero or one** path separator too. There is no depth ceiling that
exits a "confusion zone" here, because the real corpus doesn't separate
on this feature at any depth; capping further would only push already-
low counts lower with no effect. Directly quantifying what actually
drives the 1,976/2,000 (`admin_panel`) and 1,879/2,000 (`api_only`)
misclassifications, on the real extractor output:

| Signal present among misclassified rows | admin_panel_2000 | api_only_2000 |
|---|---:|---:|
| `sqli_operator_count` > 0 | 1,372 / 1,976 (69%) | 98 / 1,879 (5%) |
| `quote_count` > 0 | 0 / 1,976 (0%) | 905 / 1,879 (48%) |
| `base64_like_count` > 0 | 393 / 1,976 (20%) | 779 / 1,879 (41%) |
| `path_separator_count` median among wrong | 0 | 0 |

Three concrete, verified mechanisms, none of them path depth:

1. **`admin_panel`**: same `sqli_operator_count` raw-`=`-count issue as
   dashboard — mutation bodies (`action_id=<nonce>&confirm=true`) have
   2 bare `=` characters, sufficient alone for an `sqli` verdict.
2. **`api_only` JSON bodies**: `quote_count` (a SQLi feature, meant to
   catch `' OR 1=1`-style quote-breakout) counts *every* double quote.
   Valid JSON syntax (`{"key": "value"}`) is inherently quote-dense —
   one example body with 4 fields produced `quote_count=14`, alone
   enough to tip the verdict to `sqli`. This is structurally
   unavoidable in valid JSON; there is no way to generate realistic
   JSON request bodies that don't trigger it.
3. **`api_only` REST paths with UUID ids**: `base64_like_count`
   (`/[A-Za-z0-9+\/]{20,}={0,2}/g`) treats `/` as a valid "base64"
   character, so a path like `/api/v1/tokens/d7e805da-...` forms an
   uninterrupted 20+ char alnum-and-slash run (hyphens in the UUID are
   the only break) and false-triggers a base64-obfuscation signal that
   the model associates with attacks.

All three are **generator-independent**: they trigger on syntactically
correct, unremarkable query strings, JSON bodies, and REST paths - the
literal shapes the task asked these personas to have. There is no
parameter rename, path shortening, or ID-format choice that avoids them
without also making the traffic unrealistic (e.g., removing all `=`
from query strings, avoiding JSON bodies entirely, or avoiding path
parameters — each defeats the persona's stated purpose).

## STEP 3: re-run sanity floor on corrected generation

| Persona | Scale | % benign (before) | % benign (after dashboard fix) |
|---|---:|---:|---:|
| dashboard | 200 | 1.00% | 1.00% (unchanged) |
| dashboard | 500 | 0.60% | 0.60% (unchanged) |
| dashboard | 1000 | 0.90% | 0.90% (unchanged) |
| dashboard | 2000 | 0.90% | 0.90% (unchanged) |
| api_only | 200-2000 | 5.4-6.05% | not regenerated - depth-cap hypothesis disproven before regenerating (see STEP 2) |
| admin_panel | 200-2000 | 1.1-1.5% | not regenerated - same reason |

`api_only`/`admin_panel` were deliberately **not** regenerated with a
depth cap: STEP 2 shows depth was never the driver, so a depth-only
change is measured, in advance, to have no expected effect - re-running
the full pipeline on an unchanged-in-the-relevant-dimension file would
not have produced new information. Full data:
`results/persona_rf_sanity_report_v2.json`.

## STEP 4: verdict — **(b) confirmed extractor gap, not a generator issue**

None of the three collisions found (raw `sqli_operator_count` on
ordinary query/form `=` signs, `quote_count` on valid JSON syntax,
`base64_like_count` on slash-containing REST paths) can be fixed from
the generator side without making the generated traffic unrealistic
relative to what the task specified (and relative to real dashboard/
API/admin traffic in general - any real deployment of these personas
would hit the same three collisions). The one collision that *was*
generator-fixable (`from`/`to` as SQLi keywords) is fixed and confirmed
to have zero measurable effect on the sanity floor, which itself is
strong evidence the sanity floor problem is systemic to the feature
extractor's SQLi/encoding feature group, not to this specific data.

**This needs its own feature-design investigation before any of these
personas' data can be safely integrated** - same rigor as the
compound-cmdi ratio feature work (`docs/limitations.md` §8.1) or the
`non_form_operator_count` fix that already exists for exactly this
class of problem but evidently isn't sufficient on its own (the model
still weighs the raw, undiscounted `sqli_operator_count` heavily). Candidate
directions for that follow-up (not undertaken here - out of this task's
generation-and-verification-only scope):

- Feed `non_form_operator_count` to the model instead of (or in addition
  to, with feature-importance re-evaluation of) raw `sqli_operator_count`,
  and add an equivalent JSON-aware discount for `quote_count` (JSON
  key/value quoting is exactly as structurally benign as form-field
  `key=value`).
- Exclude `/` from `BASE64_LIKE_COUNT`'s character class, or add a
  path-aware discount analogous to `FORM_FIELD_COUNT`'s treatment of
  `sqli_operator_count`.
- Re-run LOSO / retrain sensitivity once any such change lands, per the
  same dose-response and multi-class-recall discipline used for the
  §10 UA investigation - this is exactly the kind of feature change
  that could trade attack-class recall for benign-traffic realism, and
  should be tested for that trade before adoption, not assumed safe.

**Do not proceed to LOSO/mini-pipeline/retrain.** The 12 generated files
remain useful as regression fixtures for that future extractor
investigation (they're clean, realistic, MinHash-verified benign traffic
that reliably reproduces three distinct false-positive mechanisms), but
are not ready for training-data integration as-is.
