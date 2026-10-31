import type { AuditResult } from "../types.js";
import { countBySeverity } from "./common.js";

export interface JsonOptions {
  name: string;
  version: string;
}

/** Stable, machine-readable report. No timestamps and no absolute paths, so equal input gives equal output. */
export function renderJson(result: AuditResult, options: JsonOptions): string {
  const doc = {
    tool: { name: "saas-audit", version: options.version },
    project: options.name,
    summary: { total: result.findings.length, suppressed: result.suppressed.length, bySeverity: countBySeverity(result.findings) },
    stats: result.stats,
    findings: result.findings,
    suppressed: result.suppressed,
    warnings: result.warnings,
    notes: result.notes,
  };
  return JSON.stringify(doc, null, 2) + "\n";
}
