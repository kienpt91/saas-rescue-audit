import type { AuditResult, Finding, Severity } from "../types.js";
import { SEVERITIES } from "../types.js";
import { configLines, countBySeverity, plural } from "./common.js";
import { terminalText } from "./text.js";

const COLORS: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };

export interface HumanOptions {
  color: boolean;
  name: string;
  version: string;
}

export function renderHuman(result: AuditResult, options: HumanOptions): string {
  // every string from the audited repository goes through t(), which makes it safe for a terminal
  const t = terminalText;
  const paint = (code: string, text: string): string => (options.color ? `\u001b[${code}m${text}\u001b[0m` : text);
  const lines: string[] = [];
  const s = result.stats;
  lines.push(paint("1", `saas-audit ${options.version}: ${t(options.name)}`));
  lines.push(`Scanned ${plural(s.filesScanned, "file")}: ${s.sourceFiles} JS/TS, ${s.sqlFiles} SQL (${plural(s.tablesFound, "table")}, ${plural(s.policiesFound, "policy", "policies")}), ${plural(s.routeHandlers, "route handler")}, ${plural(s.serverActions, "server action")}, ${plural(s.clientComponents, "client component")}.`);
  const config = configLines(result.config);
  if (config.length > 0) {
    lines.push("Configuration in effect:");
    for (const c of config) lines.push(`  - ${t(c)}`);
  }
  lines.push("");

  const render = (f: Finding): void => {
    lines.push(`${paint(COLORS[f.severity], f.severity.toUpperCase().padEnd(8))} ${paint("1", t(f.rule))}  ${t(f.file)}:${f.line}`);
    lines.push(`  ${t(f.title)}`);
    lines.push(`  Why:      ${t(f.message)}`);
    f.evidence.split("\n").forEach((e, i) => lines.push(`  ${i === 0 ? "Evidence:" : "         "} ${t(e)}`));
    lines.push(`  Fix:      ${t(f.fix)}`);
    lines.push("");
  };
  result.findings.forEach(render);

  const counts = countBySeverity(result.findings);
  const parts = SEVERITIES.map((sev) => `${counts[sev]} ${sev}`).join(", ");
  lines.push(result.findings.length === 0 ? "No findings." : `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}: ${parts}.`);
  if (result.suppressed.length > 0) {
    lines.push(`${plural(result.suppressed.length, "finding")} not counted:`);
    for (const f of result.suppressed) lines.push(`  - ${f.severity} ${t(f.rule)} ${t(f.file)}:${f.line} (${t(f.suppressedBy)})`);
  }
  if (result.skipped.length > 0) {
    lines.push("");
    lines.push(paint("31", `Not analysed (${result.skipped.length}): this audit is incomplete.`));
    for (const k of result.skipped) lines.push(`  - ${t(k)}`);
  }
  for (const w of result.warnings) lines.push(paint("33", `warning: ${t(w)}`));
  if (result.notes.length > 0) {
    lines.push("");
    lines.push("Not assessed for this project:");
    for (const n of result.notes) lines.push(`  - ${t(n)}`);
  }
  lines.push("");
  lines.push("This is static analysis, not a penetration test or a review. See README for what is not checked.");
  return lines.join("\n") + "\n";
}
