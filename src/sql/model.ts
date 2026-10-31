/**
 * Builds a small model (tables, RLS state, policies) from SQL migration text.
 * Only the statements that matter for row-level security are interpreted:
 * CREATE/ALTER/DROP TABLE, ALTER TABLE ... ROW LEVEL SECURITY and
 * CREATE/ALTER/DROP POLICY. Everything else is ignored.
 */
import { tokenize, type Token } from "./tokenizer.js";

export type PolicyCommand = "all" | "select" | "insert" | "update" | "delete";

export interface ColumnInfo {
  name: string;
  /** The column has a foreign key to auth.users. */
  refsAuthUsers: boolean;
}

export interface TableInfo {
  schema: string;
  name: string;
  file: string;
  line: number;
  columns: ColumnInfo[];
  rlsEnabled: boolean;
}

export interface PolicyInfo {
  name: string;
  table: string;
  command: PolicyCommand;
  /** Lower-case role names. `public` when no TO clause was given. */
  roles: string[];
  permissive: boolean;
  using: Token[] | null;
  check: Token[] | null;
  file: string;
  line: number;
}

export interface SqlModel {
  /** Keyed by `schema.name`, lower-case. Only tables created by the scanned migrations. */
  tables: Map<string, TableInfo>;
  policies: PolicyInfo[];
}

const CONSTRAINT_STARTS = new Set(["constraint", "primary", "foreign", "unique", "check", "like", "exclude"]);
const COMMANDS = new Set(["all", "select", "insert", "update", "delete"]);

export function tableKey(schema: string, name: string): string {
  return `${schema}.${name}`.toLowerCase();
}

interface Name {
  schema: string | null;
  name: string;
  next: number;
}

function readName(tokens: Token[], at: number): Name | null {
  const first = tokens[at];
  if (!first || (first.kind !== "word" && first.kind !== "qident")) return null;
  const sep = tokens[at + 1];
  const second = tokens[at + 2];
  if (sep && sep.text === "." && second && (second.kind === "word" || second.kind === "qident")) {
    return { schema: first.kind === "word" ? first.value : first.value.toLowerCase(), name: second.value, next: at + 3 };
  }
  return { schema: null, name: first.value, next: at + 1 };
}

/** Index of the token that closes the parenthesis opened at `open`, or -1. */
export function matchParen(tokens: Token[], open: number): number {
  let depth = 0;
  for (let i = open; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.kind !== "punct") continue;
    if (t.text === "(") depth++;
    else if (t.text === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function splitTopLevel(tokens: Token[], from: number, to: number): Token[][] {
  const parts: Token[][] = [];
  let depth = 0;
  let cur: Token[] = [];
  for (let i = from; i < to; i++) {
    const t = tokens[i]!;
    if (t.kind === "punct") {
      if (t.text === "(") depth++;
      else if (t.text === ")") depth--;
      else if (t.text === "," && depth === 0) {
        parts.push(cur);
        cur = [];
        continue;
      }
    }
    cur.push(t);
  }
  if (cur.length > 0) parts.push(cur);
  return parts;
}

function splitStatements(tokens: Token[]): Token[][] {
  const out: Token[][] = [];
  let cur: Token[] = [];
  for (const t of tokens) {
    if (t.kind === "punct" && t.text === ";") {
      if (cur.length > 0) out.push(cur);
      cur = [];
    } else cur.push(t);
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

function refsAuthUsers(tokens: Token[]): boolean {
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i]!.value !== "references") continue;
    const name = readName(tokens, i + 1);
    if (name && name.schema === "auth" && name.name.toLowerCase() === "users") return true;
  }
  return false;
}

function parseColumns(tokens: Token[], openParen: number): ColumnInfo[] {
  const close = matchParen(tokens, openParen);
  const end = close === -1 ? tokens.length : close;
  const columns: ColumnInfo[] = [];
  const tableLevelFks: { cols: string[]; refs: boolean }[] = [];
  for (const item of splitTopLevel(tokens, openParen + 1, end)) {
    const head = item[0];
    if (!head) continue;
    if (head.kind === "word" && CONSTRAINT_STARTS.has(head.value)) {
      // [CONSTRAINT name] FOREIGN KEY (a, b) REFERENCES auth.users
      const fk = item.findIndex((t) => t.value === "foreign");
      if (fk !== -1 && item[fk + 1]?.value === "key" && item[fk + 2]?.text === "(") {
        const c = matchParen(item, fk + 2);
        const cols = item.slice(fk + 3, c === -1 ? item.length : c).filter((t) => t.text !== ",").map((t) => t.value.toLowerCase());
        tableLevelFks.push({ cols, refs: refsAuthUsers(item) });
      }
      continue;
    }
    columns.push({ name: head.value.toLowerCase(), refsAuthUsers: refsAuthUsers(item) });
  }
  for (const fk of tableLevelFks) {
    if (!fk.refs) continue;
    for (const col of columns) if (fk.cols.includes(col.name)) col.refsAuthUsers = true;
  }
  return columns;
}

function parseExpr(tokens: Token[], at: number): { expr: Token[]; next: number } | null {
  if (tokens[at]?.text !== "(") return null;
  const close = matchParen(tokens, at);
  if (close === -1) return { expr: tokens.slice(at + 1), next: tokens.length };
  return { expr: tokens.slice(at + 1, close), next: close + 1 };
}

interface PolicyParts {
  command?: PolicyCommand;
  roles?: string[];
  permissive?: boolean;
  using?: Token[];
  check?: Token[];
}

function parsePolicyClauses(tokens: Token[], from: number): PolicyParts {
  const parts: PolicyParts = {};
  let i = from;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t.value === "as" && (tokens[i + 1]?.value === "permissive" || tokens[i + 1]?.value === "restrictive")) {
      parts.permissive = tokens[i + 1]!.value === "permissive";
      i += 2;
    } else if (t.value === "for" && tokens[i + 1] && COMMANDS.has(tokens[i + 1]!.value)) {
      parts.command = tokens[i + 1]!.value as PolicyCommand;
      i += 2;
    } else if (t.value === "to") {
      const roles: string[] = [];
      i++;
      while (i < tokens.length) {
        const r = tokens[i]!;
        if (r.kind === "word" || r.kind === "qident") {
          if (r.kind === "word" && (r.value === "using" || r.value === "with")) break;
          roles.push(r.kind === "word" ? r.value : r.value.toLowerCase());
          i++;
          if (tokens[i]?.text === ",") i++;
          else break;
        } else break;
      }
      parts.roles = roles;
    } else if (t.value === "using") {
      const e = parseExpr(tokens, i + 1);
      if (!e) break;
      parts.using = e.expr;
      i = e.next;
    } else if (t.value === "with" && tokens[i + 1]?.value === "check") {
      const e = parseExpr(tokens, i + 2);
      if (!e) break;
      parts.check = e.expr;
      i = e.next;
    } else i++;
  }
  return parts;
}

export function buildSqlModel(files: ReadonlyArray<{ path: string; text: string }>): SqlModel {
  const model: SqlModel = { tables: new Map(), policies: [] };
  const ordered = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const file of ordered) {
    for (const stmt of splitStatements(tokenize(file.text))) applyStatement(model, file.path, stmt);
  }
  return model;
}

function applyStatement(model: SqlModel, file: string, s: Token[]): void {
  const verb = s[0]?.value;
  if (verb === "create") createStatement(model, file, s);
  else if (verb === "alter") alterStatement(model, file, s);
  else if (verb === "drop") dropStatement(model, s);
}

function createStatement(model: SqlModel, file: string, s: Token[]): void {
  let i = 1;
  let temporary = false;
  while (s[i] && ["global", "local", "temporary", "temp", "unlogged"].includes(s[i]!.value)) {
    if (s[i]!.value === "temporary" || s[i]!.value === "temp") temporary = true;
    i++;
  }
  if (s[i]?.value === "table") {
    if (temporary) return;
    i++;
    if (s[i]?.value === "if" && s[i + 1]?.value === "not" && s[i + 2]?.value === "exists") i += 3;
    const name = readName(s, i);
    if (!name) return;
    const schema = name.schema ?? "public";
    if (schema !== "public") return;
    const columns = s[name.next]?.text === "(" ? parseColumns(s, name.next) : [];
    model.tables.set(tableKey(schema, name.name), { schema, name: name.name, file, line: s[0]!.line, columns, rlsEnabled: false });
    return;
  }
  if (s[i]?.value === "policy") {
    const polName = s[i + 1];
    if (!polName || s[i + 2]?.value !== "on") return;
    const table = readName(s, i + 3);
    if (!table) return;
    const parts = parsePolicyClauses(s, table.next);
    model.policies.push({
      name: polName.value,
      table: tableKey(table.schema ?? "public", table.name),
      command: parts.command ?? "all",
      roles: parts.roles && parts.roles.length > 0 ? parts.roles : ["public"],
      permissive: parts.permissive ?? true,
      using: parts.using ?? null,
      check: parts.check ?? null,
      file,
      line: s[0]!.line,
    });
  }
}

function alterStatement(model: SqlModel, file: string, s: Token[]): void {
  void file;
  if (s[1]?.value === "policy") {
    const polName = s[2];
    if (!polName || s[3]?.value !== "on") return;
    const table = readName(s, 4);
    if (!table) return;
    const key = tableKey(table.schema ?? "public", table.name);
    const existing = model.policies.find((p) => p.table === key && p.name === polName.value);
    if (!existing) return;
    const parts = parsePolicyClauses(s, table.next);
    if (parts.roles && parts.roles.length > 0) existing.roles = parts.roles;
    if (parts.using) existing.using = parts.using;
    if (parts.check) existing.check = parts.check;
    return;
  }
  if (s[1]?.value !== "table") return;
  let i = 2;
  if (s[i]?.value === "if" && s[i + 1]?.value === "exists") i += 2;
  if (s[i]?.value === "only") i++;
  const name = readName(s, i);
  if (!name) return;
  const table = model.tables.get(tableKey(name.schema ?? "public", name.name));
  if (!table) return;
  for (const action of splitTopLevel(s, name.next, s.length)) {
    const a = action.map((t) => t.value);
    if (a[0] === "enable" && a[1] === "row" && a[2] === "level" && a[3] === "security") table.rlsEnabled = true;
    else if (a[0] === "disable" && a[1] === "row" && a[2] === "level" && a[3] === "security") table.rlsEnabled = false;
    else if (a[0] === "add") {
      let k = 1;
      if (a[k] === "column") k++;
      if (a[k] === "if" && a[k + 1] === "not" && a[k + 2] === "exists") k += 3;
      const head = action[k];
      if (head && (head.kind === "word" || head.kind === "qident") && !(head.kind === "word" && CONSTRAINT_STARTS.has(head.value))) {
        table.columns.push({ name: head.value.toLowerCase(), refsAuthUsers: refsAuthUsers(action.slice(k)) });
      }
    }
  }
}

function dropStatement(model: SqlModel, s: Token[]): void {
  if (s[1]?.value === "table") {
    let i = 2;
    if (s[i]?.value === "if" && s[i + 1]?.value === "exists") i += 2;
    while (i < s.length) {
      const name = readName(s, i);
      if (!name) break;
      const key = tableKey(name.schema ?? "public", name.name);
      model.tables.delete(key);
      model.policies = model.policies.filter((p) => p.table !== key);
      i = name.next;
      if (s[i]?.text === ",") i++;
      else break;
    }
  } else if (s[1]?.value === "policy") {
    let i = 2;
    if (s[i]?.value === "if" && s[i + 1]?.value === "exists") i += 2;
    const polName = s[i];
    if (!polName || s[i + 1]?.value !== "on") return;
    const table = readName(s, i + 2);
    if (!table) return;
    const key = tableKey(table.schema ?? "public", table.name);
    model.policies = model.policies.filter((p) => !(p.table === key && p.name === polName.value));
  }
}

/** True for `true`, `(true)` and `1 = 1`, which allow every row. */
export function isConstantTrue(expr: Token[] | null): boolean {
  if (!expr) return false;
  let t = expr;
  while (t.length >= 2 && t[0]!.text === "(" && matchParen(t, 0) === t.length - 1) t = t.slice(1, -1);
  if (t.length === 1 && t[0]!.value === "true") return true;
  if (t.length === 3 && t[0]!.kind === "number" && t[1]!.text === "=" && t[2]!.kind === "number" && t[0]!.value === t[2]!.value) return true;
  return false;
}

/** True when the expression mentions the identifier (case-insensitive), qualified or not. */
export function referencesColumn(expr: Token[] | null, column: string): boolean {
  if (!expr) return false;
  const wanted = column.toLowerCase();
  return expr.some((t) => (t.kind === "word" || t.kind === "qident") && t.value.toLowerCase() === wanted);
}
