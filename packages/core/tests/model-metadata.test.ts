import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadIfThreshold, PARITY_REPORT_FILENAME } from "../src/model-metadata";

const TRAINING_MODELS_DIR = path.join(__dirname, "../../../training/models");
const SHIPPED_MODELS_DIR = path.join(__dirname, "../models");

function readThreshold(dir: string): number {
  return JSON.parse(fs.readFileSync(path.join(dir, PARITY_REPORT_FILENAME), "utf8")).threshold_if;
}

describe("loadIfThreshold", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "lsg-meta-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("returns threshold_if from parity_report.json", () => {
    fs.writeFileSync(path.join(tmpDir, PARITY_REPORT_FILENAME), JSON.stringify({ threshold_if: 0.0042 }));
    expect(loadIfThreshold(tmpDir)).toBe(0.0042);
  });

  test("throws when parity_report.json is missing", () => {
    expect(() => loadIfThreshold(tmpDir)).toThrow(/cannot read/);
  });

  test("throws when parity_report.json is not valid JSON", () => {
    fs.writeFileSync(path.join(tmpDir, PARITY_REPORT_FILENAME), "{not json");
    expect(() => loadIfThreshold(tmpDir)).toThrow(/not valid JSON/);
  });

  test("throws when threshold_if is absent or non-numeric", () => {
    fs.writeFileSync(path.join(tmpDir, PARITY_REPORT_FILENAME), JSON.stringify({ threshold_if: "0.004" }));
    expect(() => loadIfThreshold(tmpDir)).toThrow(/numeric "threshold_if"/);
  });
});

describe("shipped model metadata", () => {
  test("packages/core/models/parity_report.json matches the training source of truth", () => {
    expect(readThreshold(SHIPPED_MODELS_DIR)).toBe(readThreshold(TRAINING_MODELS_DIR));
  });
});
