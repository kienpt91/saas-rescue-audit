import { basename } from "node:path";
import { SEVERITIES, SEVERITY_RANK, type EffectiveConfig, type Finding, type Project, type Severity } from "../types.js";

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function filterMinSeverity(findings: readonly Finding[], min: Severity): Finding[] {
  return findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[min]);
}

/** Name from package.json when present, else the directory name. Untrusted: sanitize before printing. */
export function projectName(project: Project): string {
  const text = project.files.get("package.json");
  if (text) {
    try {
      const pkg: unknown = JSON.parse(text);
      if (typeof pkg === "object" && pkg !== null && "name" in pkg && typeof pkg.name === "string" && pkg.name !== "") return pkg.name.slice(0, 214);
    } catch {
      // fall through to the directory name
    }
  }
  return basename(project.root) || "project";
}

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** `plural(2, "file")` is "2 files"; pass the plural form when it is irregular. */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

const LIST_LABELS: [keyof EffectiveConfig, string][] = [
  ["ignoreRules", "rules switched off (ignoreRules)"],
  ["ignorePaths", "paths excluded (ignorePaths)"],
  ["publicRoutes", "routes treated as public (publicRoutes)"],
  ["authHelpers", "extra auth helpers (authHelpers)"],
  ["tenantColumns", "extra owner columns (tenantColumns)"],
  ["sanitizers", "extra sanitizers (sanitizers)"],
  ["dataAccessRoots", "extra database clients (dataAccessRoots)"],
  ["idempotencyHelpers", "extra idempotency helpers (idempotencyHelpers)"],
  ["rateLimiters", "extra rate limiters (rateLimiters)"],
];

/**
 * The settings that narrowed or changed this run, as plain-text lines (untrusted text: the caller
 * sanitizes). Empty when the run used no config and skipped nothing by name.
 */
export function configLines(config: EffectiveConfig): string[] {
  const lines: string[] = [];
  for (const [key, label] of LIST_LABELS) {
    const value = config[key];
    if (Array.isArray(value) && value.length > 0) lines.push(`${label}: ${value.join(", ")}`);
  }
  if (config.ignoredPathCount > 0) lines.push(`ignorePaths excluded ${plural(config.ignoredPathCount, "path")}`);
  if (config.skippedDirs.length > 0) lines.push(`directories skipped by name (dependencies and build output): ${config.skippedDirs.join(", ")}`);
  if (lines.length > 0) lines.unshift(config.source ? `settings from ${config.source}` : "no config file");
  return lines;
}

export { SEVERITIES };
