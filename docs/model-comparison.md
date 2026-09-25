# RF/IF vs MLP/Autoencoder — Comparative Benchmark (Task A34)

Empirical backing for Marco Teorico Section 6.8's architecture decision
(Random Forest + Isolation Forest over MLP + Autoencoder), which until this
task was justified only by citing Berman et al.'s general finding, not by
this project's own measured data.

All numbers in this document are read directly from JSON artifacts
committed under `training/results/baselines/` — none are hand-typed or
estimated. Regenerate with:

```
cd training/baselines
python3 train_rf_if_current_split.py
python3 train_mlp.py
python3 train_autoencoder.py
python3 measure_production_cost.py
python3 build_comparison_table.py   # prints the table below
```

`evaluate_test_once.py` is **not** part of that list — see Section 3.

## 1. Reproducibility check (Step 1)

Confirmed, with one caveat, not glossed over:

- **RF reproduces exactly.** Clearing every generated artifact
  (`unified.jsonl`, `features.{csv,parquet}`, `splits/*.parquet`) and
  re-running `training/ct_pipeline.py` end to end on this branch reproduced
  rf_v11's committed `macro_f1` and all four per-class F1 values to 16
  significant digits (`0.9809735241123363`) — bit-for-bit, not
  approximately.
- **IF reproduces closely, not exactly**, when run on this branch: 0.9133
  recall / 0.0580 FP vs the committed 0.9157 / 0.0596. Root cause: this
  branch's own prior commit (`f15e7cc`) added a 76th extractor feature
  (`non_json_quote_count`) as an unpromoted candidate — production
  `if.onnx` still expects 63 inputs. Testing on this branch means testing a
  76-feature world against 63-feature committed numbers; the gap is that
  divergence, not a reproducibility failure of the pipeline itself.
- **A literal "clean git clone" reproduction is not actually possible.**
  `training/data_clean/*.jsonl` (898 MB of raw corpus) is entirely
  gitignored — a fresh `git clone` gets zero training data. Reproducibility
  depends on that corpus persisting on disk/backup outside version control.
  Worth stating precisely in the thesis rather than claiming "reproducible
  from a clean checkout" without qualification.
- Attempting to reproduce against the exact historical commit that produced
  rf_v11/if_v10 (`734c24f`, 2026-08-30) surfaced that `ct_pipeline.py`
  itself has since been patched twice (a `None`→`0` NaN-backfill fix, and
  an unrelated notebook feature-count drift documented separately in
  project memory) — the tooling used to check reproducibility has evolved
  since that commit, so a historical-commit rerun is not apples-to-apples.
  The well-posed question — does today's committed pipeline reproduce
  today's committed metrics — is the one answered above.

## 2. Methodology

- **Split**: identical `training/splits/{train,val,test}.parquet` for all
  four models (`training/split.py`, `RANDOM_STATE=42`, locked via
  `test.lock.sha256`).
- **Feature contracts**: RF/MLP use the exact 69-dim input `rf.onnx`
  expects; IF/Autoencoder use the exact 63-dim input `if.onnx` expects
  (`training/baselines/common.py`, copied from notebooks 03/04, with
  `non_json_quote_count` additionally excluded so the comparison isn't
  contaminated by this branch's unpromoted 76-dim candidate — see Section 1).
- **RF/IF were retrained, not reused from `rf.onnx`/`if.onnx` directly.**
  A sanity check scoring the committed `rf.onnx` against the current
  `val.parquet` gave macro F1 0.9899, not the committed 0.9810 — the
  committed ONNX models were trained on an older data snapshot
  (`734c24f`); the corpus has grown since (curated telemetry, new synthetic
  sources). Scoring a stale model against a newer split would not be the
  "exact same split" comparison this task asked for. `train_rf_if_current_
  split.py` retrains RF/IF with their production hyperparameters
  (`n_estimators=30, max_depth=25` / `n_estimators=200, max_samples=4096,
  contamination=0.05`, both `random_state=42`) on the current split —
  confirmed to reproduce the committed val metrics closely (0.9807 vs
  0.9810 macro F1) before being used as this comparison's RF/IF.
- **MLP**: `MLPClassifier(64, 32)` behind a `StandardScaler`, adam solver
  (gradient descent + backprop, matching Section 6.8's own description),
  ~6,725 trainable parameters — sized to the same order of magnitude a real
  deployment would consider under the project's 5 ms p95 budget, not picked
  to flatter or sandbag either model.
- **Autoencoder**: `MLPRegressor(32, 8, 32)` trained X→X on benign-only
  data (mirrors IF's benign-only discipline exactly), bottleneck=8 <
  63 input dims, `StandardScaler` fit on benign train only (reconstruction
  error is scale-sensitive; IF, being tree-based, does not need this).
  Threshold selected the same way IF's is — maximize recall subject to
  FP ≤ 0.06 — with one **necessary fix**: the notebook 04 sweep spaces
  thresholds linearly over `[scores.min(), scores.max()]`, which works for
  IF's bounded isolation score but is silently wrong for MSE reconstruction
  error, whose distribution is heavily right-skewed (a handful of
  extreme-error attacks dominate the range). Linear spacing found a recall
  of 0.023 at first — not because the autoencoder fails, but because 299 of
  300 candidate thresholds landed in the outlier tail. Switching to
  quantile-spaced thresholds (`np.quantile(scores, linspace(0,1,300))`)
  found 0.9148 recall at FP=0.0557 — line-for-line the same selection rule,
  correctly applied to a differently-shaped score distribution.
- **R2 (locked test set, one-time read)**: `evaluate_test_once.py` is the
  single script that reads `test.parquet`. It scores all four models in one
  execution and writes `test_set_comparison.json`. This is also the first
  test-set confirmation ever recorded for an rf_v11/if_v10-generation model
  (the prior one on file, `training/results/v10_test_results.json`, is for
  rf_v10/if_v9) — one read covering both this task's comparison and that
  model generation's own R2 confirmation, not two separate reads. **Do not
  re-run `evaluate_test_once.py`**; treat a second execution against the
  same `test.parquet` with the same care as any other R2 violation.
- **Cost measurement** (`measure_production_cost.py`, `train_mlp.py`,
  `train_autoencoder.py`): p50/p95 single-request latency via ONNX Runtime
  (`CPUExecutionProvider`), 2,000 timed calls after a 50-call warmup, one
  row at a time (matches production's per-request inference shape, not a
  batched benchmark). Uses `val.parquet` inputs only — a latency
  measurement needs no labels and doesn't touch the locked test set.

## 3. Comparative table

| Modelo | Tipo | F1/Recall (test, R2 one-time read) | Latencia inferencia (p95) | Tamano modelo serializado |
|--------|------|-------------------------------------|----------------------------|----------------------------|
| Random Forest (rf_v11) | Supervisado | Macro F1=0.9776 (cmdi=0.924, path_traversal=0.983, sqli=0.996, xss=0.988) | 0.0062 ms | 8.49 MB |
| MLP | Supervisado | Macro F1=0.9719 (cmdi=0.907, path_traversal=0.974, sqli=0.995, xss=0.986) | 0.0074 ms | 28.2 KB |
| Isolation Forest (if_v10) | No supervisado | Recall=0.9125, FP=0.0546 | 0.7441 ms | 2.06 MB |
| Autoencoder | No supervisado | Recall=0.9158, FP=0.0517 | 0.0065 ms | 19.3 KB |

Source artifacts: `training/results/baselines/test_set_comparison.json`,
`mlp_metadata.json`, `autoencoder_metadata.json`, `production_cost.json`,
`rf_if_current_split_metadata.json`.

## 4. What the measured numbers actually say

**Supervised side (RF vs MLP): the thesis's framing holds, barely.** Both
classifiers land within 0.6pp macro F1 of each other on test — MLP is not
meaningfully less accurate. RF is faster (0.0062 ms vs 0.0074 ms p95) and,
counter to the usual intuition, RF's file is ~300x *larger* than the MLP's
(8.49 MB vs 28.2 KB) — a 30-tree ensemble of depth-25 trees serializes to
far more bytes than a two-hidden-layer network with ~6,700 parameters. The
real argument for RF over this particular MLP is not "smaller and faster"
across the board; it's the ~1.2 µs latency edge at effectively identical
accuracy, at a scale (µs, not ms) where both are negligible against the
project's 5 ms budget. Section 6.8 should be corrected to reflect this
precisely rather than imply a large across-the-board cost gap that these
numbers don't show.

**Unsupervised side (IF vs Autoencoder): the measured result inverts the
thesis's framing.** The autoencoder matches IF's recall/FP at the same
operating point (0.9158/0.0517 vs 0.9125/0.0546) while being ~115x faster
(0.0065 ms vs 0.7441 ms p95) and ~108x smaller (19.3 KB vs 2.06 MB). IF's
latency cost comes from its own production hyperparameters — 200 trees at
`max_samples=4096` (set for calibration stability, see if_v8 in project
history) vs RF's 30 trees — and, per a spot-check, from skl2onnx's
isolation-forest export being a materially less efficient ONNX subgraph
than its random-forest export, not from the algorithm family itself. This
is a genuine, measured finding, not an artifact of this benchmark's setup:
**on this specific project's data and production hyperparameters, the
autoencoder alternative is not the more expensive option for the
unsupervised half of the pipeline — it's the cheaper one.** IF was kept
after this measurement for reasons the thesis should state as such: it
holds no blocking authority in the current architecture (`docs/decision-
policy.md`), so its higher latency is fully absorbed by the fire-and-forget
async dispatch pattern (`worker.ts`) and never sits on the request's
critical path — a design fact, not a cost argument. Presenting Section 6.8
as "both alternatives cost more" would not survive this table; presenting
it as "RF's accuracy-for-cost tradeoff is favorable, and IF's higher
measured cost is architecturally absorbed rather than avoided" does.
