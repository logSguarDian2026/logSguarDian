// run-corpus.js — fires a sample of the logSguarDian test corpus
// (500-line JSONL with 100 payloads per class: sqli, xss, path_traversal,
// cmdi, benign) against DVNA's real, confirmed-vulnerable endpoints.
//
// DVNA only exposes 3 of the 4 categories logsguardian covers (see
// docs/dvna-logsguardian-report.md, Paso 2): SQLi (POST /app/usersearch,
// field "login"), XSS (POST /app/products, field "name"), Command Injection
// (POST /app/ping, field "address"). There is no path traversal / LFI sink
// in DVNA (confirmed by code audit: no fs.readFile/sendFile/res.download
// taking user input; express.static only serves a fixed folder and
// sanitises traversal itself). path_traversal payloads are intentionally
// NOT sent anywhere — sending them at an unrelated endpoint would not test
// what the category claims to test, and the task instructions explicitly
// forbid inventing an endpoint that doesn't exist.
//
// Usage:
//   node attack-sim/run-corpus.js --mode=before --out=results-before.json
//   node attack-sim/run-corpus.js --mode=after  --out=results-after.json
//
// --mode=before: the target server must be running with logsguardian fully
//   disabled (LOGSGUARDIAN_DISABLED=true) for its whole lifetime.
// --mode=after: the target server must be running WITH logsguardian active
//   (default block mode). Because logging in through /login is itself
//   deterministically blocked at the default threshold (see report, Paso 5
//   / "problemas de integración"), this script bootstraps the session by
//   dropping the server's `.logsguardian-disabled` toggle file for the
//   login step only, then removing it again before firing the actual
//   attack corpus, so the corpus is measured against a fully protected
//   instance.

const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.TARGET_URL || 'http://localhost:9191';
const CORPUS_PATH = '/Users/xtsebas/Universidad/logSguarDian/e2e/fixtures/test_payloads.jsonl';
const TOGGLE_FILE = path.join(__dirname, '..', '.logsguardian-disabled');

const TEST_USER = { username: 'alice', password: 'alice12345' };
const DEFAULT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

function parseArgs() {
  const args = { mode: 'before', n: 40, out: null };
  for (const arg of process.argv.slice(2)) {
    const m = arg.match(/^--([^=]+)=(.*)$/);
    if (m) args[m[1]] = m[2];
  }
  if (!args.out) args.out = `results-${args.mode}.json`;
  args.n = parseInt(args.n, 10);
  return args;
}

function loadCorpus() {
  const lines = fs.readFileSync(CORPUS_PATH, 'utf8').trim().split('\n');
  const byClass = {};
  for (const line of lines) {
    const rec = JSON.parse(line);
    const label = rec.label;
    if (!byClass[label]) byClass[label] = [];
    byClass[label].push(rec);
  }
  return byClass;
}

// Deterministic sample: take every Nth record spread across the 100 so the
// sample isn't just the first N rows (those tend to cluster on one source
// site in this corpus).
function sample(records, n) {
  const step = records.length / n;
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(records[Math.floor(i * step)]);
  }
  return out;
}

function safeDecode(s) {
  if (s == null) return '';
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return s;
  }
}

// Pick the field most likely to carry the attack signal: body first (most
// often the deliberate injection point when populated), then query, then
// path (the majority carrier for this corpus — see report for per-class
// field-population stats: sqli signal lives in `path` 94/100 times).
function pickSignal(rec) {
  if (rec.body) return safeDecode(rec.body);
  if (rec.query) return safeDecode(rec.query);
  if (rec.path) return safeDecode(rec.path);
  return '';
}

const CATEGORY_CONFIG = {
  sqli: { route: '/app/usersearch', field: 'login' },
  xss: { route: '/app/products', field: 'name' },
  cmdi: { route: '/app/ping', field: 'address' },
};

async function login(cookieJar) {
  const res = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': DEFAULT_UA,
    },
    body: new URLSearchParams({ username: TEST_USER.username, password: TEST_USER.password }).toString(),
    redirect: 'manual',
  });
  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) {
    throw new Error(`login failed: status=${res.status}, no set-cookie header (body-or-block response follows)\n${await res.text().catch(() => '')}`);
  }
  return setCookie.split(';')[0];
}

// DVNA's own product-search handler can hang indefinitely on certain
// multi-byte payloads (a real bug found while building this corpus: a
// MySQL "Illegal mix of collations" error inside an unguarded .then() with
// no .catch() leaves the request promise unresolved — see report). Guard
// every request with a hard timeout so one bad payload can't stall the
// whole batch.
const REQUEST_TIMEOUT_MS = 10000;

async function sendAttack(cookie, category, payloadText, userAgent) {
  const { route, field } = CATEGORY_CONFIG[category];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}${route}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': userAgent || DEFAULT_UA,
        Cookie: cookie,
      },
      body: new URLSearchParams({ [field]: payloadText }).toString(),
      redirect: 'manual',
      signal: controller.signal,
    });
    let predictedClass = null;
    if (res.status === 403) {
      const bodyText = await res.text().catch(() => '');
      try {
        predictedClass = JSON.parse(bodyText).class || null;
      } catch (e) {
        // non-JSON 403 body, leave predictedClass null
      }
    }
    return { status: res.status, predictedClass };
  } catch (err) {
    if (err.name === 'AbortError') {
      return { status: 'timeout', predictedClass: null };
    }
    return { status: 'error', predictedClass: null };
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const args = parseArgs();
  console.log(`mode=${args.mode} n_per_class=${args.n} base=${BASE_URL} out=${args.out}`);

  if (args.mode === 'after') {
    // Bootstrap: temporarily disable protection just to obtain a session.
    fs.writeFileSync(TOGGLE_FILE, '1');
    console.log('toggle file written — protection disabled for login bootstrap');
  }

  let cookie;
  try {
    cookie = await login();
    console.log('login OK, cookie acquired');
  } finally {
    if (args.mode === 'after' && fs.existsSync(TOGGLE_FILE)) {
      fs.unlinkSync(TOGGLE_FILE);
      console.log('toggle file removed — protection re-enabled for the corpus run');
    }
  }

  const corpus = loadCorpus();
  const results = {};

  for (const category of Object.keys(CATEGORY_CONFIG)) {
    const records = corpus[category];
    if (!records || !records.length) {
      console.warn(`no corpus records for category=${category}, skipping`);
      continue;
    }
    const picked = sample(records, Math.min(args.n, records.length));
    const rows = [];
    for (const rec of picked) {
      const payloadText = pickSignal(rec);
      const { status, predictedClass } = await sendAttack(cookie, category, payloadText, rec.userAgent);
      rows.push({ status, predictedClass, payloadPreview: payloadText.slice(0, 80) });
    }
    const statusCounts = {};
    const classCounts = {};
    let blocked = 0;
    for (const r of rows) {
      statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;
      if (r.status === 403) {
        blocked++;
        if (r.predictedClass) classCounts[r.predictedClass] = (classCounts[r.predictedClass] || 0) + 1;
      }
    }
    results[category] = { total: rows.length, blocked, statusCounts, classCounts, rows };
    console.log(
      `${category}: ${blocked}/${rows.length} blocked (${((blocked / rows.length) * 100).toFixed(1)}%) status=${JSON.stringify(statusCounts)} predictedClass=${JSON.stringify(classCounts)}`
    );
  }

  fs.writeFileSync(path.join(__dirname, args.out), JSON.stringify(results, null, 2));
  console.log(`results written to attack-sim/${args.out}`);
}

main().catch((err) => {
  console.error(err);
  // Make sure we never leave protection accidentally disabled on a crash.
  if (fs.existsSync(TOGGLE_FILE)) fs.unlinkSync(TOGGLE_FILE);
  process.exit(1);
});
