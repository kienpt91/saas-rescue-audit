import { BudgetError, withBudget, type Limits } from "../limits.js";
import { evidenceLine } from "../redact.js";
import { buildSqlModel, type SqlModel } from "../sql/model.js";
import { parseProject, TooDeepError, type SourceInfo } from "../ts/source.js";
import type { Config, Project, RawFinding } from "../types.js";

export interface AuditContext {
  project: Project;
  config: Config;
  limits: Limits;
  sources: SourceInfo[];
  /** Tables and policies from supabase/migrations/*.sql and supabase/schema.sql. */
  sql: SqlModel;
  sqlFiles: string[];
  /** Things worth saying that do not reduce coverage. */
  warnings: string[];
  /** Files or parts of the project that were not analysed, as "path: reason". */
  skipped: string[];
  /**
   * Runs one file's worth of analysis. A file that takes too long, nests too deeply or makes
   * the analysis fail is recorded as skipped instead of stopping the whole audit.
   */
  guard: (path: string, fn: () => void) => void;
}

export type Rule = (ctx: AuditContext) => RawFinding[];

const MIGRATION_PATH = /(?:^|\/)supabase\/(?:migrations\/.+|schema)\.sql$/;

export function describeFailure(error: unknown): string {
  if (error instanceof BudgetError) return "analysis stopped: time budget exceeded";
  if (error instanceof TooDeepError) return error.message;
  if (error instanceof RangeError) return "analysis stopped: nesting too deep";
  if (error instanceof Error) return `analysis failed: ${error.name}: ${error.message.slice(0, 120)}`;
  return "analysis failed";
}

export function createContext(project: Project, config: Config, limits: Limits): AuditContext {
  const warnings: string[] = [];
  const skipped: string[] = [...project.skipped];
  const guard = (path: string, fn: () => void): void => {
    try {
      withBudget(limits.fileBudgetMs, fn);
    } catch (error) {
      const reason = `${path}: ${describeFailure(error)}`;
      if (!skipped.includes(reason)) skipped.push(reason);
    }
  };
  const sqlFiles = [...project.files.keys()].filter((p) => MIGRATION_PATH.test(p)).sort();
  const sql = buildSqlModel(
    sqlFiles.map((path) => ({ path, text: project.files.get(path)! })),
    { guard, warn: (message) => warnings.push(message) },
  );
  const sources = parseProject(project, limits, skipped);
  return { project, config, limits, sources, sql, sqlFiles, warnings, skipped, guard };
}

let cachedText: string | null = null;
let cachedLines: string[] = [];
const cachedEvidence = new Map<number, string>();

/** 1-based line of a text file as evidence: trimmed, scrubbed of credential-shaped substrings, truncated. */
export function textLine(text: string, line: number, max = 180): string {
  if (cachedText !== text) {
    cachedText = text;
    cachedLines = text.split(/\r?\n/);
    cachedEvidence.clear();
  }
  const key = line * 1000 + max;
  let out = cachedEvidence.get(key);
  if (out === undefined) {
    out = evidenceLine(cachedLines[line - 1] ?? "", max);
    cachedEvidence.set(key, out);
  }
  return out;
}
