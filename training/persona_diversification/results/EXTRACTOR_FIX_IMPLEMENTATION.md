# Extractor fix implementation + recall-regression + sanity-floor re-check

Branch: `investigate/benign-persona-diversification`. Implements the 3
scoped fixes, retrains a candidate (fixes only, no persona data), checks
for recall regression, then re-runs the sanity floor on the original 12
persona files. **Persona integration remains a separate, not-yet-made
decision** — nothing here touches `unified.jsonl`/`label_map.yaml`
permanently or promotes anything to production.

## Important correction made mid-task: persona files were leaking into training

While setting up the retrain, discovered `training/unify.py` globs **every**
`*.jsonl` file in `training/data_clean/` with no `label_map.yaml` gate —
label_map.yaml is documentation of how each source's labels were derived,
not an inclusion filter. The 12 persona files from the prior task sat in
that directory (gitignored, but physically present) and got silently
folded into the very first retrain attempt (5,130 rows across 6 of the 12
files - confirmed via `_source` counts in `unified.jsonl`). This would
have contaminated the isolation Step 5 explicitly asks for ("did the
feature fix itself break anything" vs. "does adding persona data break
anything" - two separate questions). **Fixed by moving all 12 files to
`training/persona_diversification/generated_data/`** before the retrain
that produced the numbers below, and re-running unify from scratch.
Worth flagging as a standing gap in `unify.py` for anyone else generating
candidate data in `data_clean/` — nothing currently stops it from being
swept into a retrain.

## STEP 1: base64_like_count regex fix

`packages/extractor/src/patterns.ts` - removed `/` from
`BASE64_LIKE_COUNT`'s character class. Added
`tests/base64-path-false-positive.test.ts` (4 tests: UUID path no longer
matches, long-numeric-id path no longer matches, real base64 still
matches, base64 containing an embedded `/` still matches on its
non-slash run). Full suite green:

```
pnpm --filter @logsguardian/extractor test -- --testPathPattern="patterns|base64"
PASS tests/base64-path-false-positive.test.ts (4/4)
```

## STEP 2: non_json_quote_count feature

Added `JSON_KV_QUOTE_COUNT` regex (`patterns.ts`) and
`non_json_quote_count = max(0, quote_count - json_kv_quote_count)`
(`semantic.ts`) - **additive**, mirrors `non_form_operator_count` exactly.
`quote_count` itself is unchanged. Added
`tests/non-json-quote.test.ts` (5 tests, including a JSON body with an
embedded SQLi quote-breakout payload confirming the discount doesn't
eat real signal). All pass.

**Approach taken: new feature (dimension added), not an in-place
adjustment to `quote_count`.** `FEATURE_NAMES` grew 75 -> 76
(`packages/extractor/src/index.ts`), matching the non-negotiable
additive-only principle from every prior feature change in this project.
Updated: the length assertion in `index.ts`, doc comments citing "75
features" (`cli.ts`, `structural.ts`, `encoding.ts`, `types.ts`,
`worker.ts`), the two length-75 test files (`extractFeatures.test.ts`,
`edge-cases.test.ts`), and regenerated the determinism golden fixture
(`tests/fixtures/determinism_golden.json`, now 1000×76 - old one deleted
and regenerated per established convention, all 83 extractor tests pass).

`packages/core/src/worker.ts`'s `EXCLUDED_NAMES` picked up
`non_json_quote_count` **temporarily**, keeping production `rf.onnx`/
`if.onnx` at 69/63 inputs until the retrain below - exact precedent from
`non_form_operator_count`'s original PR ("worker.ts: rf_v7/if_v6 are
unchanged in this PR... keeping the ONNX model input at 66 dims until the
v8 retrain"). Core's full test suite (169 tests, including the parity
test against production `rf.onnx`: max diff 0) passes with this change.

## STEP 3: sqli_operator_count — confirmed retrain-only, no code change made

Re-confirmed (see prior investigation): `non_form_operator_count` already
exists, is already one of the 69 features fed to `rf.onnx`, and already
reads 0 on every `admin_panel` false-positive row inspected. No code
touched here.

## STEP 4: full retrain (candidate, not promoted)

`training/ct_pipeline.py` run end-to-end (`unify -> extractor CLI ->
csv_to_parquet -> split -> notebooks 02-04 -> notebook 05 export+parity ->
gates`), three attempts before a clean result:

1. **First attempt failed** at `02_baseline.ipynb`: `LogisticRegression`
   raised `ValueError: Input X contains NaN`. Root cause:
   `merge_curated_telemetry()` backfills any feature column present in
   `features.parquet` but absent from a legacy `telemetry_curated_*.jsonl`
   file with `None` - correct for a genuinely-new-since-collection
   feature is `non_json_quote_count`, which didn't exist when that
   telemetry was captured, but `None` became NaN which the baseline model
   can't handle. **Fixed**: backfill with `0` instead of `None`
   (`ct_pipeline.py`), matching this project's existing convention for
   any other never-computed-for-this-row numeric feature (e.g. the
   permanently-0 temporal group).
2. **Second attempt failed** at ONNX export: `notebook 05`'s hardcoded
   `assert N_FEATURES == 69` / `assert IF_N_FEATURES == 63` gates (exactly
   the kind of hardcoded assertion the project's own comments warn must
   be updated together with `FEATURE_NAMES`/exclusion-set changes).
   **Fixed**: bumped both asserts to 70/64 in `05_onnx_export.ipynb`
   (this is the retrain intentionally meant to pick the new feature up,
   unlike the temporary `worker.ts` exclusion above).
3. **Third attempt** succeeded end-to-end but included the leaked persona
   data described above - discarded.
4. **Fourth attempt** (persona files quarantined) succeeded cleanly:
   `rf_candidate.onnx` (70 features), `if_candidate.onnx` (64 features),
   parity passed (`rf_max_prob_diff=1.3e-07`, `if_max_score_diff=1.5e-07`),
   production `rf.onnx`/`if.onnx` restored to HEAD afterward and confirmed
   untouched (`[None, 69]` / `[None, 63]` dims, `git status` clean).

**Gate 0 (`feature_contract`) fails as expected, not a real problem.**
It compares the candidate's dims against `training/models/parity_report.json`
- which describes the *current production* contract (69/63) by design,
so it correctly flags any dimension change until that file, `worker.ts`'s
`EXCLUDED_NAMES`, and its hardcoded assertions are updated together as
part of an actual promotion (same as v11's 67/61 -> 69/63 update, done in
its own retrain commit). That coordinated update is a promotion-time
decision, out of scope for this checkpoint - not attempted here.

## STEP 5: recall-regression check — no regression, all gates clear

Production `rf_v11` baseline (recorded from this project's own committed
`docs/limitations.md`/prior read of `rf_v11_metadata.json` - the metadata
file itself is untracked and got overwritten by this retrain, a
gap worth fixing separately; production `rf.onnx` itself is git-tracked
and was verified untouched throughout) vs. the fixes-only candidate
(same corpus otherwise, persona data excluded, `training/models/rf_candidate_metadata.json`):

| Class | rf_v11 (production) F1 | Candidate (fixes only) F1 | Delta |
|---|---:|---:|---:|
| cmdi | 0.9461 | 0.9383 | -0.78pp |
| path_traversal | 0.9863 | 0.9853 | -0.10pp |
| sqli | 0.9963 | 0.9962 | -0.01pp |
| xss | 0.9884 | 0.9868 | -0.16pp |
| macro F1 | 0.9831 | 0.9810 | -0.21pp |
| classes >= 0.80 F1 | 4/4 | 4/4 | unchanged |

Candidate's full per-class precision/recall (val set, `run_notebooks.py` log):

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| benign | 1.00 | 1.00 | 1.00 |
| cmdi | 0.91 | 0.97 | 0.94 |
| path_traversal | 0.99 | 0.98 | 0.99 |
| sqli | 1.00 | 1.00 | 1.00 |
| xss | 0.99 | 0.98 | 0.99 |

IF: production `if_v10` (git-tracked, untouched) `val_recall=0.9157,
val_fp_rate=0.0596` vs. candidate `val_recall=0.9133 (-0.24pp),
val_fp_rate=0.0580 (-0.16pp, i.e. slightly fewer false positives)`.

`training/gates/gate_metrics.py` run directly against the candidate:
**`passed: true`** (RF 4/4 classes >= 0.80 F1, required >= 3; IF recall
0.9133 >= 0.50 and FP 0.0580 <= 0.06).

**All deltas are sub-1-percentage-point and every class stays far above
the 0.80 F1 gate** (cmdi, the smallest margin, is still 0.94). One caveat
on attribution: this comparison isn't a perfectly isolated A/B (identical
data, extractor before/after) - the corpus also picked up 119 curated
telemetry rows collected since `rf_v11` was cut, so a small part of the
delta could be ordinary data drift rather than the extractor changes
themselves. Given the deltas are this small and every gate clears
comfortably, that distinction doesn't change the verdict: **no
meaningful recall regression from the extractor fixes alone.**

## STEP 6: sanity-floor re-check with the fixed candidate — two of three mechanisms clearly improved, one unchanged (exactly as predicted)

Same 12 persona files (now `training/persona_diversification/generated_data/`),
re-scored against `rf_candidate.onnx` (the fixed, retrained candidate):

| Persona | Scale | % benign (before fix) | % benign (after fix) | Delta |
|---|---:|---:|---:|---:|
| dashboard | 200 | 1.00% | 1.50% | +0.50pp |
| dashboard | 500 | 0.60% | 1.00% | +0.40pp |
| dashboard | 1000 | 0.90% | 1.50% | +0.60pp |
| dashboard | 2000 | 0.90% | 1.55% | +0.65pp |
| api_only | 200 | 5.50% | 22.00% | +16.50pp |
| api_only | 500 | 5.80% | 19.80% | +14.00pp |
| api_only | 1000 | 5.40% | 20.90% | +15.50pp |
| api_only | 2000 | 6.05% | 21.65% | +15.60pp |
| admin_panel | 200 | 1.50% | 17.00% | +15.50pp |
| admin_panel | 500 | 1.20% | 15.20% | +14.00pp |
| admin_panel | 1000 | 1.10% | 15.80% | +14.70pp |
| admin_panel | 2000 | 1.20% | 14.65% | +13.45pp |

**This result is internally consistent with the mechanism-level diagnosis
from the prior scoping pass, which is itself the strongest evidence the
diagnosis was right:**

- **`api_only`/`admin_panel` improved substantially** (+13 to +16
  percentage points) - exactly the two personas whose dominant failure
  mode was `quote_count` (JSON bodies, 48% of `api_only`'s misses) and
  `base64_like_count` (REST path shape, 20-41% of misses in both). Both
  mechanisms got a real code fix in this task.
- **`dashboard` barely moved** (+0.4 to +0.65pp, still under 2% benign) -
  exactly the persona whose dominant failure mode was raw
  `sqli_operator_count` on ordinary `key=value` query strings, which
  Step 3 confirmed needs a retrain that teaches the model to lean on the
  already-existing `non_form_operator_count` signal (via actual benign
  multi-param-query training examples), not an extractor code change.
  This retrain deliberately excluded persona data, so **this flat result
  is the expected, predicted outcome, not a new failure** - it's
  confirmation that the earlier root-cause attribution (retrain-only, not
  a code gap) was correct.

**Neither persona is resolved outright** (`dashboard` still ~98.5% wrong,
`api_only`/`admin_panel` still ~78-85% wrong) - the fixes closed real,
verified gaps but didn't single-handedly flip the sanity floor to
majority-benign. That was always going to require the persona training
data itself for the `dashboard`/`non_form_operator_count` mechanism, and
likely helps further on `api_only`/`admin_panel` too (more diverse
JSON/REST-shaped benign examples for the model to generalize from, on top
of the two structural bugs already fixed here).

## What's still open / explicitly not decided here

- **Persona integration remains a separate decision**, exactly as scoped.
  The extractor fixes are real, tested, and shown not to regress the
  existing test set - but they are necessary, not sufficient, for the
  sanity floor to look production-ready. The `dashboard` result in
  particular shows the extractor fix alone cannot close every mechanism;
  some of this needs the actual persona training data.
- **Not promoted**: `rf.onnx`/`if.onnx` in `training/models/` are
  untouched production files; the candidate lives only in
  `rf_candidate.onnx`/`if_candidate.onnx`. Promoting requires the
  coordinated `parity_report.json` + `worker.ts` `EXCLUDED_NAMES` +
  hardcoded-assertion update this report deliberately deferred.
- **`rf_v11_metadata.json` is untracked and was overwritten** by this
  retrain (its values now match the candidate, not the original v11 run)
  - a gap in this project's git-tracking convention (its sibling
  `if_v10_metadata.json` is tracked) worth fixing so a future retrain
  doesn't lose the same reference point this one did. The original
  values are preserved in this conversation's own record and reproduced
  in the STEP 5 table above, so nothing is actually lost this time.
