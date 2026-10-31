import { basename } from "node:path";
import { SEVERITIES, SEVERITY_RANK, type Finding, type Project, type Severity } from "../types.js";

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function filterMinSeverity(findings: readonly Finding[], min: Severity): Finding[] {
  return findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[min]);
}

/** Name from package.json when present, else the directory name. */
export function projectName(project: Project): string {
  const text = project.files.get("package.json");
  if (text) {
    try {
      const pkg: unknown = JSON.parse(text);
      if (typeof pkg === "object" && pkg !== null && "name" in pkg && typeof pkg.name === "string" && pkg.name !== "") return pkg.name;
    } catch {
      // fall through to the directory name
    }
  }
  return basename(project.root) || "project";
}

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export { SEVERITIES };

/** `plural(2, "file")` is "2 files"; pass the plural form when it is irregular. */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}
