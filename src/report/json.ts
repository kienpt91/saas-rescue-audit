import type { AuditResult } from "../types.js";
import { countBySeverity } from "./common.js";

export interface JsonOptions {
  name: string;
  version: string;
}

/**
 * Stable, machine-readable report. No timestamps and no absolute paths, so equal input gives equal
 * output. Text from the audited repository is kept exactly as found (JSON escapes control characters),
 * so a consumer that renders it must sanitize it for its own sink.
 */
export function renderJson(result: AuditResult, options: JsonOptions): string {
  const doc = {
    tool: { name: "saas-audit", version: options.version },
    project: options.name,
    complete: result.skipped.length === 0,
    summary: { total: result.findings.length, suppressed: result.suppressed.length, bySeverity: countBySeverity(result.findings) },
    stats: result.stats,
    config: result.config,
    findings: result.findings,
    suppressed: result.suppressed,
    skipped: result.skipped,
    warnings: result.warnings,
    notes: result.notes,
  };
  return JSON.stringify(doc, null, 2) + "\n";
}
