/** @type {import('jest').Config} */
module.exports = {
  roots: ["<rootDir>/src", "<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  projects: [
    {
      displayName: "default",
      testEnvironment: "node",
      testMatch: ["<rootDir>/tests/**/*.test.ts"],
      // cli-config-set.test.ts is run separately (package.json's "test" script,
      // second `jest` invocation, --runInBand) — it's the one file in this
      // suite with an unexplained, real but rare (order of 1 in 10-20 full-
      // suite runs) flake where it reads back a value that belongs to a
      // DIFFERENT test, despite being 100% synchronous with no yield points
      // (confirmed via 20/20 clean runs in complete isolation — the bug is
      // real cross-file/cross-worker interference, root cause not found
      // after substantial investigation). Isolating it to run alone, in its
      // own process, is the honest fix for the actual failure mode — a
      // dedicated process can't be corrupted by any other file's leaked
      // handle, whatever it turns out to be.
      // smoke.test.ts's "with real models" test is excluded here (not via
      // CI's CLI flags) deliberately: a CLI-level --testPathIgnorePatterns
      // *replaces* this array instead of merging with it, which previously
      // silently un-excluded cli-config-set.test.ts in CI and reintroduced
      // the exact interference flake this array exists to prevent (see
      // .github/workflows/ci.yml's test-core step history). Keeping every
      // permanent exclusion here, never on the CLI, is the actual fix.
      testPathIgnorePatterns: ["parity.node.test.ts", "cli-config-set.test.ts", "smoke.test.ts"],
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
      // See the "default" project's testPathIgnorePatterns comment — this
      // file is deliberately excluded there and run alone here instead
      // (package.json's "test" script's second `jest` invocation targets
      // this project by name via --selectProjects).
      displayName: "cli-config-set-isolated",
      testEnvironment: "node",
      testMatch: ["<rootDir>/tests/cli-config-set.test.ts"],
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.test.json", diagnostics: { ignoreCodes: [151002] } }],
      },
    },
  ],
};
