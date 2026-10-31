import { buildSqlModel, type SqlModel } from "../sql/model.js";
import { parseProject, type SourceInfo } from "../ts/source.js";
import type { Config, Project, RawFinding } from "../types.js";

export interface AuditContext {
  project: Project;
  config: Config;
  sources: SourceInfo[];
  /** Tables and policies from supabase/migrations/*.sql and supabase/schema.sql. */
  sql: SqlModel;
  sqlFiles: string[];
}

export type Rule = (ctx: AuditContext) => RawFinding[];

const MIGRATION_PATH = /(?:^|\/)supabase\/(?:migrations\/.+|schema)\.sql$/;

export function createContext(project: Project, config: Config): AuditContext {
  const sqlFiles = [...project.files.keys()].filter((p) => MIGRATION_PATH.test(p)).sort();
  const sql = buildSqlModel(sqlFiles.map((path) => ({ path, text: project.files.get(path)! })));
  return { project, config, sources: parseProject(project), sql, sqlFiles };
}

/** 1-based line of a text file, trimmed and truncated. */
export function textLine(text: string, line: number, max = 180): string {
  const raw = text.split(/\r?\n/)[line - 1] ?? "";
  const t = raw.trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
}
