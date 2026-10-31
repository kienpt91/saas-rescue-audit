import { createContext, textLine, type Rule } from "./rules/context.js";
import { authRules } from "./rules/auth.js";
import { injectionRules } from "./rules/injection.js";
import { secretRules } from "./rules/secrets.js";
import { stripeRules } from "./rules/stripe.js";
import { supabaseRules } from "./rules/supabase.js";
import { applySuppressions } from "./suppress.js";
import { SEVERITY_RANK, type AuditResult, type Config, type Finding, type Project } from "./types.js";

const RULE_SETS: readonly Rule[] = [supabaseRules, secretRules, stripeRules, authRules, injectionRules];

export function compareFindings(a: Finding, b: Finding): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
}

/** Runs every rule over the project. Pure: no I/O, no network, same input gives the same output. */
export function audit(project: Project, config: Config): AuditResult {
  const ctx = createContext(project, config);
  const ignored = new Set(config.ignoreRules);

  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const rule of RULE_SETS) {
    for (const raw of rule(ctx)) {
      if (ignored.has(raw.rule)) continue;
      const key = `${raw.rule}|${raw.file}|${raw.line}|${raw.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ ...raw, evidence: raw.evidence ?? textLine(project.files.get(raw.file) ?? "", raw.line) });
    }
  }
  findings.sort(compareFindings);

  const outcome = applySuppressions(findings, project.files, ignored);

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
    findings: outcome.kept,
    suppressed: outcome.suppressed,
    warnings: [...project.warnings, ...outcome.warnings],
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
  };
}
