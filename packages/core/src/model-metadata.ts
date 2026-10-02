import fs from "node:fs";
import path from "node:path";

export const PARITY_REPORT_FILENAME = "parity_report.json";

/**
 * Reads the Isolation Forest anomaly threshold calibrated alongside the
 * shipped if.onnx. The value lives in parity_report.json (written by the
 * retrain pipeline next to the ONNX export) so it can never drift from the
 * model it belongs to, unlike a constant maintained by hand.
 *
 * Throws instead of falling back to a default: a silently wrong threshold
 * flags the wrong requests as anomalous with no visible symptom.
 */
export function loadIfThreshold(modelDir: string): number {
  const reportPath = path.join(modelDir, PARITY_REPORT_FILENAME);

  let raw: string;
  try {
    raw = fs.readFileSync(reportPath, "utf8");
  } catch (err) {
    throw new Error(
      `logsguardian: cannot read ${reportPath} (needed for the IF anomaly threshold): ${(err as Error).message}`,
    );
  }

  let report: { threshold_if?: unknown };
  try {
    report = JSON.parse(raw);
  } catch (err) {
    throw new Error(`logsguardian: ${reportPath} is not valid JSON: ${(err as Error).message}`);
  }

  const threshold = report.threshold_if;
  if (typeof threshold !== "number" || !Number.isFinite(threshold)) {
    throw new Error(`logsguardian: ${reportPath} has no numeric "threshold_if"`);
  }
  return threshold;
}
