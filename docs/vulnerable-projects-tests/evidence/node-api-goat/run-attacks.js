// Replays a sample of the shared logSguarDian test corpus
// (../../../logSguarDian/e2e/fixtures/test_payloads.jsonl, read-only, not
// this repo) against node-api-goat's real endpoints, over real HTTP.
//
// Sampling: the corpus is laid out as 5 contiguous 100-line blocks, one per
// class (sqli, xss, path_traversal, cmdi, benign). We take every 2nd line
// within each block (indices 0,2,4,...,98) -> 50 samples/class, 250 total.
// 50/class is on the high end of the 30-50 guidance because the corpus has
// zero empty-payload records (verified separately) and the run completes in
// well under a minute, so there was no time-budget reason to cut it down --
// more samples means a tighter estimate of the block rate per class.
//
// Endpoint mapping (see ../VULN-MAPPING.md for the full rationale):
//   xss            -> GET /cwe79/echo?text=<payload>          (real XSS sink)
//   path_traversal -> GET /cwe73/read?foo=<payload>           (real LFI/path traversal sink)
//   cmdi           -> GET /cwe78/childprocess?foo=<payload>   (real OS command injection sink)
//   sqli           -> GET /cwe201/exposure?text=<payload>     (NO real SQL sink in this app --
//                                                               node-api-goat has no database at
//                                                               all. This route is a neutral,
//                                                               otherwise-unused "echo" carrier
//                                                               used ONLY to exercise
//                                                               logsguardian's detection surface
//                                                               on sqli-shaped payloads. Blocking
//                                                               here reflects detection capability,
//                                                               NOT a fixed node-api-goat SQLi vuln.)
//   benign         -> GET /hexToRgb?hex=<payload>              (app's one non-CWE utility route,
//                                                               used as a neutral carrier for
//                                                               normal-looking traffic)
//
// Each corpus record can carry its payload in body, query, or path
// (whichever is non-empty, in that preference order) and is frequently
// percent-encoded as it would appear on the wire; we best-effort
// decodeURIComponent it once to recover the logical string, then let the
// URL/fetch machinery re-encode it exactly once for transmission -- matching
// what a browser send + Express's own query-string decoding would produce.

const fs = require('fs');
const path = require('path');

const CORPUS_PATH = '/Users/xtsebas/Universidad/logSguarDian/e2e/fixtures/test_payloads.jsonl';
const BASE_URL = process.env.TARGET_URL || 'http://localhost:3001';
const SAMPLES_PER_CLASS = 50;
const OUT_DIR = __dirname;

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive',
};

function extractPayload(rec) {
  let raw = '';
  if (rec.body && typeof rec.body === 'string' && rec.body.length > 0) raw = rec.body;
  else if (rec.query && rec.query.length > 0) raw = rec.query;
  else if (rec.path && rec.path.length > 0) raw = rec.path;
  try {
    return decodeURIComponent(raw);
  } catch (e) {
    return raw; // malformed percent-encoding -- send as-is
  }
}

function loadCorpus() {
  const lines = fs.readFileSync(CORPUS_PATH, 'utf8').trim().split('\n');
  const byClass = {};
  for (const line of lines) {
    const rec = JSON.parse(line);
    (byClass[rec.label] = byClass[rec.label] || []).push(rec);
  }
  const sampled = {};
  for (const [label, records] of Object.entries(byClass)) {
    sampled[label] = records.filter((_, i) => i % 2 === 0).slice(0, SAMPLES_PER_CLASS);
  }
  return sampled;
}

const ENDPOINT_BY_CLASS = {
  xss: (payload) => `${BASE_URL}/cwe79/echo?text=${encodeURIComponent(payload)}`,
  path_traversal: (payload) => `${BASE_URL}/cwe73/read?foo=${encodeURIComponent(payload)}`,
  cmdi: (payload) => `${BASE_URL}/cwe78/childprocess?foo=${encodeURIComponent(payload)}`,
  sqli: (payload) => `${BASE_URL}/cwe201/exposure?text=${encodeURIComponent(payload)}`,
  benign: (payload) => `${BASE_URL}/hexToRgb?hex=${encodeURIComponent(payload)}`,
};

async function sendOne(label, rec) {
  const payload = extractPayload(rec);
  const url = ENDPOINT_BY_CLASS[label](payload);
  try {
    const res = await fetch(url, { headers: BROWSER_HEADERS, redirect: 'manual' });
    return { status: res.status, payload_preview: payload.slice(0, 80) };
  } catch (err) {
    return { status: 'ERR', error: String(err), payload_preview: payload.slice(0, 80) };
  }
}

async function run() {
  const mode = process.argv[2] || 'unlabeled'; // 'before' | 'after'
  const corpus = loadCorpus();
  const results = {};

  for (const [label, records] of Object.entries(corpus)) {
    const statusCounts = {};
    const samples = [];
    for (const rec of records) {
      const r = await sendOne(label, rec);
      statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;
      samples.push(r);
    }
    const blocked = statusCounts['403'] || 0;
    results[label] = { total: records.length, blocked, statusCounts, samples };
    console.log(
      `[${mode}] ${label}: ${blocked}/${records.length} blocked (403)`,
      statusCounts
    );
  }

  const outFile = path.join(OUT_DIR, `results-${mode}.json`);
  fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  console.log(`\nWrote ${outFile}`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
