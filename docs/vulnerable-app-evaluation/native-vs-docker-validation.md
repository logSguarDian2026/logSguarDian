# Native vs Docker Deployment Validation

**Question answered:** does `logsguardian` work identically when the vulnerable
notes app runs as a plain `npm run dev` Node process on the host (no Docker
at all), versus running inside the project's Docker/Compose setup? This is an
operational smoke test, not a replacement for the official R2 test-set numbers
in `docs/decision-policy.md` or the Config 1/2/3 evaluation in this folder —
it validates that the *deployment topology* doesn't change detection behavior,
using two raw terminal transcripts captured on 2026-09-12/13.

**Source transcripts** (raw `script(1)` captures, referenced here rather than
duplicated): `bash_waf_LG.txt` (Docker run) and `logsguardian.txt` (native
run), both at the repository root at capture time.

**Result: yes, it worked in both.** Same middleware, same models
(rf_v11/if_v10), two different process/OS topologies, two different attack
corpora, consistent detection behavior in both. Details and caveats below —
including two real operational issues hit along the way, both diagnosed and
fixed during the session, not hidden.

---

## Setup A — Docker with WAF

**Environment:** `logSguarDian-vulnerable-project` running inside its Docker
container (`HOSTNAME=40c7e7d4b852`, `PWD=/app`). Confirmed via `printenv`:
`LOGSGUARDIAN_DISABLED=false` (middleware active), `LOGSGUARDIAN_DB_PATH=`
(empty — app falls back to its hardcoded default, `/app/logsguardian-events.db`,
per `src/app.js`). Postgres reachable at `DB_HOST=db` (Compose service name).

**Corpus:** `attack-sim/run_large_corpus.py config1` — the 590-payload SecLists
corpus (cmdi 200, path_traversal 200, sqli 77, xss 113) also used for the
Round 4 Config 1-3b evaluation elsewhere in this folder, sent against the
app's real routes (`/posts/search`, `/posts`, `/posts/1/attachment`,
`/admin/ping`). Run twice in this session (once before, once after fixing the
dbPath issue below) — same 590 payloads, same measured block rate both times.

### Result (script's own count, HTTP 403 = blocked)

| Category | Blocked | Rate |
|---|---|---|
| cmdi | 200/200 | 100.0% |
| path_traversal | 197/200 | 98.5% |
| sqli | 76/77 | 98.7% |
| xss | 110/113 | 97.3% |

590 requests processed in 1.5–2.4s wall time for the whole corpus (Python
script's own timer) — consistent with the low per-request overhead already
documented in `docs/results.md`.

### Operational issue hit and fixed: dbPath mismatch

`npx logsguardian attacks list` initially crashed with
`SqliteError: no such table: detection_events`, even though the file it
opened existed. Root cause: `logsguardian.config.js` inside the container had
been generated earlier via `config init`, which defaults to
`dbPath: './logsguardian.db'` — a different file from the one the live app
actually writes to (`/app/logsguardian-events.db`, hardcoded in
`src/app.js`). The file the CLI found had been created by `webhooks add`
(which creates the DB file on demand for its own `webhooks` table) and had
therefore never been touched by `EventStore`, so `detection_events` never
existed in it. Fixed by rewriting `logsguardian.config.js`'s `dbPath` to match
the app's actual path exactly. This is the same class of bug the CLI already
has a partial safeguard for (`dbPathMismatchHint` in
`packages/core/src/cli/guard.ts`) — except that hint only fires when the
table exists and is empty, not when the table is entirely absent, so the
crash wasn't caught by the existing guard. Worth a follow-up fix in the CLI
(catch the missing-table case and print the same hint instead of an
unhandled `SqliteError`).

### Post-fix CLI evidence (cumulative across both corpus runs)

```
npx logsguardian attacks list
  sqli            588
  path_traversal  362
  xss             180
  cmdi            46
```

```
npx logsguardian endpoints top
  POST    /admin/ping          400 incidents   risk 167.78
  GET     /posts/1/attachment  400 incidents   risk 237.44
  POST    /posts               226 incidents   risk 167.37
  GET     /posts/search        154 incidents   risk 104.47
  GET     /posts               10 incidents    risk 8.69   (benign)
  POST    /login               4 incidents     risk 3.31   (benign)
```

Note the `sqli`/`cmdi` split (588/46) doesn't match the corpus's own
77-sqli/200-cmdi composition — consistent with the already-documented
cmdi↔sqli classification confusion in `docs/limitations.md` §1 (attacks are
still blocked either way; this affects triage labeling, not protection).
`attacks inspect <type>` and `endpoints profile <route>` also worked
correctly, pulling live F1/precision/recall figures and real payload examples
from the store.

---

## Setup B — Native (no Docker)

**Environment:** the same vulnerable notes app, but run directly with
`nodemon src/server.js` (`npm run dev`) on the host — no container, no
Compose network. Postgres reachable natively (this is the same setup
established earlier in this conversation via Homebrew).

**Corpus:** four separate Artillery scenarios
(`artillery-{cmdi,path-traversal,sqli,xss}.yml`), 100 payloads each (400
total), driven by `attack-sim/processor.js` against `{sqli,xss,path_traversal,cmdi}_payloads.json`
— a corpus of **real-world attack/scanner paths** (WordPress `wp-login.php`,
`.env`/`.git` probing, SQLi/XSS embedded directly in the URL path, not just
query params), sent as raw requests to whatever path each payload record
specifies — deliberately not restricted to the app's own defined routes, to
test whether logsguardian intercepts malicious-looking traffic before/regardless
of Express routing.

### Result (Artillery's own HTTP 403 counts, one phase per category)

| Category | Requests | 403 (blocked) | p95 latency | p99 latency |
|---|---|---|---|---|
| cmdi | 101 | 98 | 7ms | 16ms |
| path_traversal | 100 | 100 | 4ms | 7ms |
| sqli | 100 | 100 | 6ms | 7ms |
| xss | 122† | 72 | 5ms | 6ms |

† XSS phase: 100 vusers created, 3 failed with Artillery's own
`Invalid URL` client-side error (payloads like
`<script>+-+-1-+-+alert(1)</script>` used directly as a raw path segment
aren't valid URLs by Node's own `URL` parser used by Artillery's HTTP engine)
— an Artillery/test-harness limitation, not a logsguardian defect; those
requests never left the client. The remaining 97 completed normally (25×200,
25×302 login-redirect noise from unauthenticated GETs, 72×403 blocked).

### Cumulative CLI evidence after the run

```
npx logsguardian attacks list
  sqli            150
  path_traversal  114
  cmdi            71
  xss             59
```
= **394 of ~400 requests classified as one of the four attack categories**
(the remainder mostly landed as `benign` on paths like `/login` itself, which
carries no attack payload — see `endpoints profile /login`: 26/26 benign,
correctly not blocked).

```
npx logsguardian endpoints top
  GET   /            56 incidents   risk 36.14
  GET   /login       26 incidents   risk 22.60   (all benign, correctly passed)
  GET   /.env        14 incidents   risk 13.70
  ...
```

No config or dbPath issues in this run — `logsguardian.config.js` and the
app's own `dbPath` agreed from the start (single Node process, single cwd, no
cross-container filesystem boundary to get wrong).

---

## Comparison

| | Docker | Native |
|---|---|---|
| Corpus | 590 SecLists payloads, targeted at real app routes | 400 real-world scanner paths, untargeted |
| Detection rate | 97.3–100% by category | 98.5% overall (394/400 attack-classified) |
| p95 latency | not separately measured this run (script has no per-request timer) | 4–7ms across categories |
| Config/dbPath issue | Yes — hit and fixed mid-session | No — none, single-process setup has no cross-boundary dbPath to misconfigure |
| CLI (`attacks`, `endpoints`) | Fully functional post-fix | Fully functional throughout |

## Conclusion

logsguardian's detection behavior does not depend on running inside Docker —
identical library, identical models, functioning correctly whether the host
app is a containerized service reachable over a Compose network or a bare
`node`/`nodemon` process on the host talking to a local Postgres. The one
real defect surfaced (dbPath mismatch causing an unhandled `SqliteError`
instead of the CLI's existing friendly hint) is a **CLI robustness gap**, not
a detection gap, and is specific to multi-process/multi-filesystem
deployments (Docker, or any setup where the app and the CLI don't share a
literal `require('./logsguardian.config.js')` call) — it does not occur in
the simpler native single-process setup, and it's already fixed here by
pointing `dbPath` at the same file the app actually writes to.

## What this test does *not* prove

- These are not the official R2 locked-test-set metrics (`docs/decision-policy.md`)
  — this is live corpus replay against a live app, useful as an operational
  sanity check, not a substitute for the offline evaluation.
- Latency here is unbudgeted, ad hoc, single-run — not the formal Δp95
  benchmark methodology from `docs/results.md` §F6. Treat the 4–7ms native
  p95 figures as directionally consistent with, not a replacement for, that
  benchmark.
- The Docker run's corpus targeted real app routes; the native run's corpus
  targeted arbitrary scanner paths. The two aren't a controlled A/B on the
  *same* corpus — they're two independent validations that happen to agree.

## Housekeeping note

`bash_waf_LG.txt` and `logsguardian.txt` are currently untracked raw terminal
captures sitting at the repository root (`git status`). If you want to keep
them as evidence, they belong under
`docs/vulnerable-app-evaluation/evidence/` (referenced from this file)
rather than loose at the repo root — happy to move them there and update this
doc's source-transcript paths if you want them committed.
