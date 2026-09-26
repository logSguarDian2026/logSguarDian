/** @type {import('jest').Config} */

// Every CLI test file that mutates process.cwd() via a withTempDir()-style
// helper (process.chdir() into a fresh temp dir, chdir back in a finally).
// process.cwd() is a single value shared by the whole worker process, not
// per-test-file, so any two of these files sharing a process are exposed to
// the same class of interference: cli-config-set.test.ts flaked this way
// first (real, reproducible, root cause not found after substantial
// investigation), and cli-webhooks-remove.test.ts flaked the same way later.
//
// IMPORTANT: each of these files is 100% deterministic completely alone
// (verified: 8/8 and 6/6 clean runs for the two files known to have flaked,
// run solo with --runInBand). Running them all TOGETHER in one shared
// --runInBand project (an earlier version of this fix) made things WORSE,
// not better — 7/8 runs failed — because it guarantees every file shares a
// single process with 13 others instead of only occasionally colliding with
// whichever file a parallel worker happened to schedule next. The only
// pattern proven safe is: one file, alone, in its own process. See
// .github/workflows/ci.yml's test-core step and package.json's "test"
// script, which invoke this project once per file for exactly that reason
// — do not collapse that back into a single combined invocation.
const CWD_MUTATING_TESTS = [
  "cli-attacks-list.test.ts",
  "cli-attacks-inspect.test.ts",
  "cli-attacks-summary.test.ts",
  "cli-config-init.test.ts",
  "cli-config-show.test.ts",
  "cli-config-validate.test.ts",
  "cli-config-set.test.ts",
  "cli-endpoints-profile.test.ts",
  "cli-endpoints-top.test.ts",
  "cli-endpoints-report.test.ts",
  "cli-webhooks-add.test.ts",
  "cli-webhooks-test.test.ts",
  "cli-webhooks-remove.test.ts",
  "cli-webhooks-list.test.ts",
];

module.exports = {
  roots: ["<rootDir>/src", "<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  projects: [
    {
      displayName: "default",
      testEnvironment: "node",
      testMatch: ["<rootDir>/tests/**/*.test.ts"],
      // smoke.test.ts's "with real models" test is excluded here (not via
      // CI's CLI flags) deliberately: a CLI-level --testPathIgnorePatterns
      // *replaces* this array instead of merging with it, which previously
      // silently un-excluded cli-config-set.test.ts in CI and reintroduced
      // the exact interference flake this array exists to prevent (see
      // .github/workflows/ci.yml's test-core step history). Keeping every
      // permanent exclusion here, never on the CLI, is the actual fix.
      testPathIgnorePatterns: ["parity.node.test.ts", "smoke.test.ts", ...CWD_MUTATING_TESTS],
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.test.json", diagnostics: { ignoreCodes: [151002] } }],
      },
    },
    {
      displayName: "ort-parity",
      // Custom environment pins TypedArray constructors so onnxruntime-node's
      // native addon instanceof checks pass inside Jest's vm context.
      testEnvironment: "<rootDir>/jest-ort-environment.js",
      testMatch: ["<rootDir>/tests/parity.node.test.ts"],
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.test.json", diagnostics: { ignoreCodes: [151002] } }],
      },
    },
    {
      // See the CWD_MUTATING_TESTS comment above — every file here is
      // deliberately excluded from "default" and run alone, together,
      // --runInBand, in this project instead (package.json's "test" script
      // and CI's test-core step both target this project by name via
      // --selectProjects).
      displayName: "cli-cwd-isolated",
      testEnvironment: "node",
      testMatch: CWD_MUTATING_TESTS.map((f) => `<rootDir>/tests/${f}`),
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.test.json", diagnostics: { ignoreCodes: [151002] } }],
      },
    },
  ],
};
