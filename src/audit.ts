import { BudgetError, DEFAULT_LIMITS, withBudget, type Limits } from "./limits.js";
import { createContext, textLine, type Rule } from "./rules/context.js";
import { authRules } from "./rules/auth.js";
import { hygieneRules } from "./rules/hygiene.js";
import { injectionRules } from "./rules/injection.js";
import { secretRules } from "./rules/secrets.js";
import { stripeRules } from "./rules/stripe.js";
import { supabaseRules } from "./rules/supabase.js";
import { applySuppressions } from "./suppress.js";
import { SEVERITY_RANK, type AuditResult, type Config, type Finding, type Project, type SuppressedFinding } from "./types.js";

const RULE_SETS: readonly Rule[] = [supabaseRules, secretRules, stripeRules, authRules, injectionRules, hygieneRules];

export interface AuditOptions {
  /** Overrides for the resource limits. */
  limits?: Partial<Limits>;
  /** Config file the settings came from, shown in reports. */
  configSource?: string | null;
}

export function compareFindings(a: Finding, b: Finding): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
}

/** Runs every rule over the project. No network, no code execution; the same input gives the same output. */
export function audit(project: Project, config: Config, options: AuditOptions = {}): AuditResult {
  const limits: Limits = { ...DEFAULT_LIMITS, ...options.limits };
  const ignored = new Set(config.ignoreRules);

  const seen = new Set<string>();
  const all: Finding[] = [];
  const configBy = new Map<Finding, string>();
  const skippedTotal: string[] = [];

  const ctx = withBudget(limits.totalBudgetMs, () => createContext(project, config, limits));

  try {
    withBudget(limits.totalBudgetMs, () => {
      for (const rule of RULE_SETS) {
        for (const raw of rule(ctx)) {
          const key = `${raw.rule}|${raw.file}|${raw.line}|${raw.title}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const finding: Finding = {
            rule: raw.rule,
            severity: raw.severity,
            file: raw.file,
            line: raw.line,
            title: raw.title,
            message: raw.message,
            evidence: raw.evidence ?? textLine(project.files.get(raw.file) ?? "", raw.line),
            fix: raw.fix,
          };
          all.push(finding);
          if (ignored.has(raw.rule)) configBy.set(finding, "config ignoreRules");
          else if (raw.suppressedBy) configBy.set(finding, raw.suppressedBy);
        }
      }
    });
  } catch (error) {
    if (!(error instanceof BudgetError)) throw error;
    skippedTotal.push(`analysis: stopped, the total time budget of ${limits.totalBudgetMs} ms was exceeded; findings are incomplete`);
  }
  all.sort(compareFindings);

  const outcome = applySuppressions(all, project.files, ignored);
  const findings: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of outcome.kept) {
    const by = configBy.get(f);
    if (by) suppressed.push({ ...f, suppressedBy: by });
    else findings.push(f);
  }
  for (const f of outcome.suppressed) suppressed.push({ ...f, suppressedBy: "inline comment" });
  suppressed.sort(compareFindings);

  const entries = ctx.sources.flatMap((s) => s.entries);
  const notes: string[] = [];
  const usesSupabase = [...project.files.values()].some((t) => /supabase/i.test(t));
  if (ctx.sqlFiles.length === 0) {
    notes.push(
      usesSupabase
        ? "No supabase/migrations/*.sql or supabase/schema.sql found, so row level security was not assessed at all. Tables and policies created in the Supabase dashboard are invisible to this tool."
        : "No Supabase SQL files found; row level security rules had nothing to check.",
    );
  }
  if (project.gitTracked === null) {
    notes.push("No readable .git/index at the project root: whether .env files are tracked was judged from .gitignore rules only.");
  }
  if (entries.length === 0) notes.push("No route handlers, server actions or API routes were recognised, so the auth, Stripe and redirect rules had nothing to check.");

  return {
    findings,
    suppressed,
    warnings: [...project.warnings, ...ctx.warnings, ...outcome.warnings],
    skipped: [...new Set([...ctx.skipped, ...skippedTotal])].sort(),
    stats: {
      filesScanned: project.files.size,
      sourceFiles: ctx.sources.length,
      sqlFiles: ctx.sqlFiles.length,
      tablesFound: ctx.sql.tables.size,
      policiesFound: ctx.sql.policies.length,
      routeHandlers: entries.filter((e) => e.kind === "route" || e.kind === "pages-api").length,
      serverActions: entries.filter((e) => e.kind === "action").length,
      clientComponents: ctx.sources.filter((s) => s.isClient).length,
    },
    notes,
    config: { ...config, source: options.configSource ?? null, skippedDirs: project.skippedDirs, ignoredPathCount: project.ignoredByConfigCount },
  };
}
