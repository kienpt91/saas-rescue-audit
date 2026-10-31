/**
 * Inline suppression comments:
 *
 *   // saas-audit-ignore-next-line <rule>[, <rule>] [-- reason]
 *   // saas-audit-ignore-line <rule>                  (same line)
 *   // saas-audit-ignore-file <rule>                  (whole file)
 *
 * `--` comments work in SQL, `#` in env files and block comments inside JSX braces. `all` matches every rule.
 * Suppressed findings are kept and reported separately, and a directive that
 * suppresses nothing is reported as a warning so stale ones get removed.
 */
import { RULE_IDS } from "./catalog.js";
import type { Finding } from "./types.js";

export type DirectiveKind = "ignore-line" | "ignore-next-line" | "ignore-file";

export interface Directive {
  kind: DirectiveKind;
  rules: string[];
  /** Line the comment is on. */
  line: number;
  /** Line whose findings it covers (0 for file-wide). */
  target: number;
  used: boolean;
}

const DIRECTIVE = /(?:\/\/|\/\*|--|#)\s*saas-audit-(ignore-line|ignore-next-line|ignore-file)\b([^\n]*)/;

export function parseDirectives(text: string): Directive[] {
  const lines = text.split(/\r?\n/);
  const directives: Directive[] = [];
  const isDirectiveLine: boolean[] = lines.map((l) => DIRECTIVE.test(l));
  lines.forEach((lineText, idx) => {
    const m = DIRECTIVE.exec(lineText);
    if (!m) return;
    let rest = m[2] ?? "";
    const close = rest.indexOf("*/");
    if (close !== -1) rest = rest.slice(0, close);
    rest = rest.split(/\s--(?:\s|$)/)[0] ?? "";
    const rules = rest.split(/[\s,]+/).filter((r) => r !== "");
    const kind = m[1] as DirectiveKind;
    const line = idx + 1;
    let target = 0;
    if (kind === "ignore-line") target = line;
    else if (kind === "ignore-next-line") {
      target = line + 1;
      while (isDirectiveLine[target - 1]) target++;
    }
    directives.push({ kind, rules, line, target, used: false });
  });
  return directives;
}

export interface SuppressionOutcome {
  kept: Finding[];
  suppressed: Finding[];
  warnings: string[];
}

export function applySuppressions(findings: Finding[], files: ReadonlyMap<string, string>, ignoredRules: ReadonlySet<string>): SuppressionOutcome {
  const byFile = new Map<string, Directive[]>();
  const warnings: string[] = [];
  for (const [path, text] of files) {
    if (!text.includes("saas-audit-ignore")) continue;
    const directives = parseDirectives(text);
    if (directives.length === 0) continue;
    byFile.set(path, directives);
    for (const d of directives) {
      if (d.rules.length === 0) warnings.push(`${path}:${d.line}: saas-audit-${d.kind} names no rule`);
      for (const r of d.rules) {
        if (r !== "all" && !RULE_IDS.has(r)) warnings.push(`${path}:${d.line}: saas-audit-${d.kind} names unknown rule "${r}"`);
      }
    }
  }
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    const directives = byFile.get(f.file) ?? [];
    let hit = false;
    for (const d of directives) {
      const ruleMatch = d.rules.includes("all") || d.rules.includes(f.rule);
      const lineMatch = d.kind === "ignore-file" || d.target === f.line;
      if (ruleMatch && lineMatch) {
        d.used = true;
        hit = true;
      }
    }
    (hit ? suppressed : kept).push(f);
  }
  for (const [path, directives] of byFile) {
    for (const d of directives) {
      const known = d.rules.filter((r) => r === "all" || RULE_IDS.has(r));
      if (known.length === 0 || d.used) continue;
      if (known.every((r) => ignoredRules.has(r))) continue;
      warnings.push(`${path}:${d.line}: saas-audit-${d.kind} ${known.join(", ")} suppresses nothing`);
    }
  }
  return { kept, suppressed, warnings };
}
