/**
 * PLAN.md F1.8 — extractFeatureVector() latency benchmark
 *
 * Two series, reported separately and never mixed:
 *   A. direct: extractFeatureVector() on the main thread (in-process cost).
 *   B. worker_roundtrip: postMessage -> extractFeatureVector() in a
 *      worker_thread -> response, timed on the main thread. It includes
 *      structured-clone and message-passing cost, so it is not comparable
 *      with series A as extraction cost.
 *
 * Serial measurement only (not burst-fire) — burst-fire measures queuing
 * artifacts, not per-request cost (see A15/A20 latency methodology note
 * in docs/results.md). Warmup iterations are discarded.
 *
 * Each run writes benchmarks/results/extractor-<timestamp>.json.
 *
 * Run from repo root (requires packages/extractor to be built):
 *   pnpm --filter @logsguardian/extractor build
 *   node benchmarks/extractor.bench.js
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");
const { Worker, isMainThread, parentPort } = require("worker_threads");
const { extractFeatureVector, FEATURE_NAMES } = require(
  path.join(__dirname, "../packages/extractor/dist/index.js")
);

const ROOT = path.join(__dirname, "..");
const RESULTS_DIR = path.join(__dirname, "results");
const GATE_P95_MS = 1;
const PLAN_CRITERION_LABEL = "PLAN.md F1.8: p95 <= 1ms per request";

// CanonicalRequest.body is a string (not an object) — JSON bodies are
// stringified the same way middleware.ts does before calling the extractor.
const FIXTURES = [
  {
    label: "benign",
    req: {
      method: "GET",
      path: "/api/products",
      query: "category=electronics&sort=price&page=2",
      body: "",
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      contentType: "",
      referer: "https://example.com/shop",
      cookie: "session=abc123",
      extraHeaders: {},
    },
  },
  {
    label: "sqli",
    req: {
      method: "GET",
      path: "/api/users",
      query: "id=1' UNION SELECT username,password FROM users--",
      body: "",
      userAgent: "sqlmap/1.7",
      contentType: "",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "xss",
    req: {
      method: "POST",
      path: "/api/comments",
      query: "",
      body: JSON.stringify({ content: "<script>alert(document.cookie)</script>" }),
      userAgent: "Mozilla/5.0",
      contentType: "application/json",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "path_traversal",
    req: {
      method: "GET",
      path: "/api/files",
      query: "path=../../../../etc/passwd",
      body: "",
      userAgent: "curl/7.68.0",
      contentType: "",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
  {
    label: "cmdi",
    req: {
      method: "POST",
      path: "/api/ping",
      query: "",
      body: JSON.stringify({ host: "127.0.0.1; cat /etc/passwd" }),
      userAgent: "python-requests/2.28.0",
      contentType: "application/x-www-form-urlencoded",
      referer: "",
      cookie: "",
      extraHeaders: {},
    },
  },
];

const WARMUP_ITERS = 200;
const BENCH_ITERS = 2000;
const NS_PER_MS = 1_000_000;
const MS_DECIMALS = 3;

function round(value, decimals = MS_DECIMALS) {
  return Number(value.toFixed(decimals));
}

function elapsedMs(startNs) {
  return Number(process.hrtime.bigint() - startNs) / NS_PER_MS;
}

function percentile(sortedTimes, p) {
  return sortedTimes[Math.floor(sortedTimes.length * p)];
}

function summarize(timesMs) {
  const sorted = [...timesMs].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, t) => sum + t, 0) / sorted.length;
  return {
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
    mean: round(mean),
    max: round(sorted[sorted.length - 1]),
    throughput: Math.round(1000 / mean),
  };
}

function environment() {
  return {
    commit: execSync("git rev-parse HEAD", { cwd: ROOT }).toString().trim(),
    node: process.version,
    cpu: os.cpus()[0].model,
    os: `${os.type()} ${os.release()}`,
    platform: process.platform,
    arch: process.arch,
  };
}

function measureDirect(req, iters) {
  const times = new Array(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    extractFeatureVector(req);
    times[i] = elapsedMs(t0);
  }
  return times;
}

function workerRoundTrip(worker, req) {
  return new Promise((resolve) => {
    worker.once("message", resolve);
    worker.postMessage(req);
  });
}

async function measureRoundTrip(worker, req, iters) {
  const times = new Array(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    await workerRoundTrip(worker, req);
    times[i] = elapsedMs(t0);
  }
  return times;
}

function mixedRequests(total) {
  return Array.from({ length: total }, (_, i) => FIXTURES[i % FIXTURES.length].req);
}

async function runSeries(measureOne) {
  const perFixture = {};
  for (const { label, req } of FIXTURES) {
    await measureOne(req, WARMUP_ITERS);
    perFixture[label] = summarize(await measureOne(req, BENCH_ITERS));
  }
  await measureMixed(measureOne, WARMUP_ITERS);
  perFixture.mixed = summarize(await measureMixed(measureOne, BENCH_ITERS));
  return perFixture;
}

async function measureMixed(measureOne, iters) {
  const requests = mixedRequests(iters);
  const times = new Array(iters);
  for (let i = 0; i < iters; i++) {
    times[i] = (await measureOne(requests[i], 1))[0];
  }
  return times;
}

function startWorker() {
  return new Worker(__filename);
}

function printSeries(title, series) {
  console.log(`\n=== ${title} ===`);
  for (const [label, s] of Object.entries(series)) {
    console.log(`  [${label}]`);
    console.log(`    p50: ${s.p50.toFixed(3)} ms | p95: ${s.p95.toFixed(3)} ms | p99: ${s.p99.toFixed(3)} ms`);
    console.log(`    mean: ${s.mean.toFixed(3)} ms | max: ${s.max.toFixed(3)} ms | throughput: ${s.throughput.toLocaleString()} req/s`);
  }
}

function writeResults(payload) {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const stamp = payload.timestamp.replace(/[:.]/g, "-");
  const file = path.join(RESULTS_DIR, `extractor-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(payload, null, 2) + "\n");
  return file;
}

async function main() {
  const timestamp = new Date().toISOString();
  console.log(`=== logSguarDian — Extractor Benchmark (F1.8) ===`);
  console.log(`${timestamp} | Node ${process.version} | ${process.platform}/${process.arch}`);
  console.log(`Fixtures: ${FIXTURES.length} | Warmup: ${WARMUP_ITERS} | Bench: ${BENCH_ITERS} iters each | Vector: ${FEATURE_NAMES.length} features`);

  const direct = await runSeries(async (req, iters) => measureDirect(req, iters));

  const worker = startWorker();
  const roundTrip = await runSeries((req, iters) => measureRoundTrip(worker, req, iters));
  await worker.terminate();

  printSeries("SERIES A — direct, extractFeatureVector() on the main thread", direct);
  printSeries("SERIES B — worker_roundtrip (postMessage -> extractor in worker -> response), NOT extraction cost", roundTrip);

  const gate = direct.mixed.p95 <= GATE_P95_MS ? "PASS ✓" : "FAIL ✗";
  console.log(`\nGATE (series A, mixed p95 <= ${GATE_P95_MS} ms): ${gate}  — ${PLAN_CRITERION_LABEL}`);

  const file = writeResults({
    timestamp,
    environment: { ...environment(), warmup_iters: WARMUP_ITERS, bench_iters: BENCH_ITERS },
    series: {
      direct: { execution: "main thread", fixtures: direct },
      worker_roundtrip: { execution: "worker_threads round-trip, timed on main thread", fixtures: roundTrip },
    },
  });
  console.log(`\nResults written to ${path.relative(ROOT, file)}`);
}

if (isMainThread) {
  main();
} else {
  parentPort.on("message", (req) => parentPort.postMessage(extractFeatureVector(req)));
}
