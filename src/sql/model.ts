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
  /** Keyed by `schema.name`. Unquoted names are lower-cased, quoted names keep their case. Only tables created by the scanned migrations. */
  tables: Map<string, TableInfo>;
  policies: PolicyInfo[];
}

/** Model plus the index that keeps policy lookups constant-time while the migrations are applied. */
interface Builder extends SqlModel {
  index: Map<string, Map<string, PolicyInfo>>;
}

export interface BuildOptions {
  /** Runs the work for one file; lets the caller isolate failures and time limits per file. */
  guard?: (path: string, fn: () => void) => void;
  warn?: (message: string) => void;
}

const CONSTRAINT_STARTS = new Set(["constraint", "primary", "foreign", "unique", "check", "like", "exclude"]);
const COMMANDS = new Set(["all", "select", "insert", "update", "delete"]);

export function tableKey(schema: string, name: string): string {
  return `${schema}.${name}`;
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
    return { schema: first.value, name: second.value, next: at + 3 };
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

export function buildSqlModel(files: ReadonlyArray<{ path: string; text: string }>, options: BuildOptions = {}): SqlModel {
  const model: Builder = { tables: new Map(), policies: [], index: new Map() };
  const ordered = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const guard = options.guard ?? ((_path: string, fn: () => void): void => fn());
  for (const file of ordered) {
    guard(file.path, () => {
      for (const stmt of splitStatements(tokenize(file.text))) {
        applyStatement(model, file.path, stmt);
        const hidden = stmt.find((t) => t.kind === "dollar" && DOLLAR_BODY_SQL.test(t.value));
        if (hidden) options.warn?.(`${file.path}:${hidden.line}: a function or DO block mentions policies, row level security or EXECUTE; SQL inside dollar-quoted bodies is not analysed`);
      }
    });
  }
  model.policies = [...model.index.values()].flatMap((byName) => [...byName.values()]);
  return model;
}

/** Statements inside dollar-quoted bodies that this model would otherwise have interpreted. */
const DOLLAR_BODY_SQL = /\b(?:create\s+policy|alter\s+policy|drop\s+policy|alter\s+table|row\s+level\s+security|execute)\b/i;

function policyIndex(model: Builder, table: string): Map<string, PolicyInfo> {
  let byName = model.index.get(table);
  if (!byName) {
    byName = new Map();
    model.index.set(table, byName);
  }
  return byName;
}

function applyStatement(model: Builder, file: string, s: Token[]): void {
  const verb = s[0]?.value;
  if (verb === "create") createStatement(model, file, s);
  else if (verb === "alter") alterStatement(model, file, s);
  else if (verb === "drop") dropStatement(model, s);
}

function createStatement(model: Builder, file: string, s: Token[]): void {
  let i = 1;
  let temporary = false;
  while (s[i] && ["global", "local", "temporary", "temp", "unlogged"].includes(s[i]!.value)) {
    if (s[i]!.value === "temporary" || s[i]!.value === "temp") temporary = true;
    i++;
  }
  if (s[i]?.value === "table") {
    if (temporary) return;
    i++;
    let ifNotExists = false;
    if (s[i]?.value === "if" && s[i + 1]?.value === "not" && s[i + 2]?.value === "exists") {
      ifNotExists = true;
      i += 3;
    }
    const name = readName(s, i);
    if (!name) return;
    const schema = name.schema ?? "public";
    if (schema !== "public") return;
    const key = tableKey(schema, name.name);
    // CREATE TABLE IF NOT EXISTS leaves an existing table, including its RLS state, alone
    if (ifNotExists && model.tables.has(key)) return;
    const columns = s[name.next]?.text === "(" ? parseColumns(s, name.next) : [];
    model.tables.set(key, { schema, name: name.name, file, line: s[0]!.line, columns, rlsEnabled: false });
    return;
  }
  if (s[i]?.value === "policy") {
    const polName = s[i + 1];
    if (!polName || s[i + 2]?.value !== "on") return;
    const table = readName(s, i + 3);
    if (!table) return;
    const parts = parsePolicyClauses(s, table.next);
    policyIndex(model, tableKey(table.schema ?? "public", table.name)).set(polName.value, {
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

function alterStatement(model: Builder, _file: string, s: Token[]): void {
  if (s[1]?.value === "policy") {
    const polName = s[2];
    if (!polName || s[3]?.value !== "on") return;
    const table = readName(s, 4);
    if (!table) return;
    const key = tableKey(table.schema ?? "public", table.name);
    const existing = model.index.get(key)?.get(polName.value);
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

function dropStatement(model: Builder, s: Token[]): void {
  if (s[1]?.value === "table") {
    let i = 2;
    if (s[i]?.value === "if" && s[i + 1]?.value === "exists") i += 2;
    while (i < s.length) {
      const name = readName(s, i);
      if (!name) break;
      const key = tableKey(name.schema ?? "public", name.name);
      model.tables.delete(key);
      model.index.delete(key);
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
    model.index.get(key)?.delete(polName.value);
  }
}

/** Outcome of folding a boolean expression made of constants. */
export type Folded = "true" | "false" | "unknown" | "too-deep";

const MAX_FOLD_DEPTH = 64;

/** Index of the matching close parenthesis for every open one, or -1. One pass, no recursion. */
function parenTable(tokens: readonly Token[]): Int32Array {
  const close = new Int32Array(tokens.length).fill(-1);
  const stack: number[] = [];
  tokens.forEach((t, i) => {
    if (t.kind !== "punct") return;
    if (t.text === "(") stack.push(i);
    else if (t.text === ")") {
      const open = stack.pop();
      if (open !== undefined) close[open] = i;
    }
  });
  return close;
}

interface Literal {
  kind: "number" | "string" | "boolean";
  value: string | number | boolean;
}

function literalOf(tokens: readonly Token[], lo: number, hi: number): Literal | null {
  let end = hi;
  // x::type casts do not change a constant
  if (end - lo >= 3 && tokens[end - 2]!.text === "::" && tokens[end - 1]!.kind === "word") end -= 2;
  if (end - lo !== 1) return null;
  const t = tokens[lo]!;
  if (t.kind === "number") {
    const n = Number(t.value);
    return Number.isNaN(n) ? null : { kind: "number", value: n };
  }
  if (t.kind === "string") return { kind: "string", value: t.value };
  if (t.kind === "word" && (t.value === "true" || t.value === "false")) return { kind: "boolean", value: t.value === "true" };
  return null;
}

/**
 * Folds an expression that consists only of constants, parentheses, NOT, AND, OR and comparisons
 * between literals. Anything else (a column, a function call) makes that part `unknown`, but OR with
 * a true operand and AND with a false operand are still decided, so `true or user_id = auth.uid()`
 * is "true". Works on token ranges, so deep nesting costs time linear in the input, and reports
 * "too-deep" instead of guessing once logical grouping goes beyond 64 levels.
 */
export function foldConstant(expr: readonly Token[]): Folded {
  const close = parenTable(expr);
  const fold = (lo: number, hiIn: number, depth: number): Folded => {
    if (depth > MAX_FOLD_DEPTH) return "too-deep";
    let hi = hiIn;
    // peel redundant outer parentheses iteratively
    while (hi - lo >= 2 && expr[lo]!.text === "(" && close[lo] === hi - 1) {
      lo += 1;
      hi -= 1;
    }
    if (hi <= lo) return "unknown";
    const split = (word: string): number[] => {
      const at: number[] = [];
      for (let i = lo; i < hi; i++) {
        const t = expr[i]!;
        if (t.text === "(" && close[i] !== -1) i = close[i]!;
        else if (t.kind === "word" && t.value === word) at.push(i);
      }
      return at;
    };
    const combine = (word: "or" | "and"): Folded | null => {
      const at = split(word);
      if (at.length === 0) return null;
      const bounds = [lo - 1, ...at, hi];
      let unknown = false;
      for (let k = 0; k < bounds.length - 1; k++) {
        const part = fold(bounds[k]! + 1, bounds[k + 1]!, depth + 1);
        if (part === "too-deep") return "too-deep";
        if (word === "or" && part === "true") return "true";
        if (word === "and" && part === "false") return "false";
        if (part === "unknown") unknown = true;
      }
      if (unknown) return "unknown";
      return word === "or" ? "false" : "true";
    };
    const ored = combine("or");
    if (ored !== null) return ored;
    const anded = combine("and");
    if (anded !== null) return anded;
    if (expr[lo]!.kind === "word" && expr[lo]!.value === "not") {
      const inner = fold(lo + 1, hi, depth + 1);
      return inner === "true" ? "false" : inner === "false" ? "true" : inner;
    }
    const lit = literalOf(expr, lo, hi);
    if (lit && lit.kind === "boolean") return lit.value ? "true" : "false";
    // literal = literal, literal <> literal
    for (let i = lo + 1; i < hi; i++) {
      const op = expr[i]!;
      if (op.kind !== "op" || !["=", "<>", "!="].includes(op.text)) continue;
      const a = literalOf(expr, lo, i);
      const b = literalOf(expr, i + 1, hi);
      if (!a || !b || a.kind !== b.kind) return "unknown";
      return (a.value === b.value) === (op.text === "=") ? "true" : "false";
    }
    return "unknown";
  };
  return fold(0, expr.length, 0);
}

/** True when the expression is constant true (`true`, `1 = 1`, `true or x`, `not false`, ...) and allows every row. */
export function isConstantTrue(expr: Token[] | null): boolean {
  return expr !== null && foldConstant(expr) === "true";
}

/** True when the expression mentions the identifier (case-insensitive), qualified or not. */
export function referencesColumn(expr: Token[] | null, column: string): boolean {
  if (!expr) return false;
  const wanted = column.toLowerCase();
  return expr.some((t) => (t.kind === "word" || t.kind === "qident") && t.value.toLowerCase() === wanted);
}

const CALLER_IDENTITY = new Set(["uid", "jwt"]);
const NOT_A_FUNCTION = new Set(["in", "any", "all", "exists", "and", "or", "not", "select", "values", "array", "from", "where", "then", "else", "when", "case", "is", "like"]);

/**
 * True when the expression ties `column` to the caller: it mentions the column together with the
 * caller's identity (auth.uid(), auth.jwt(), current_setting(), current_user), or passes the column
 * to a function (a membership helper such as is_member(org_id)). Merely mentioning the column, as in
 * `user_id is not null`, does not scope anything.
 */
export function scopesToCaller(expr: Token[] | null, column: string): boolean {
  if (!expr || foldConstant(expr) === "true") return false;
  const wanted = column.toLowerCase();
  const mention: number[] = [];
  let identity = false;
  expr.forEach((t, i) => {
    if ((t.kind === "word" || t.kind === "qident") && t.value.toLowerCase() === wanted) mention.push(i);
    if (t.kind === "word" && t.value === "auth" && expr[i + 1]?.text === "." && CALLER_IDENTITY.has(expr[i + 2]?.value ?? "")) identity = true;
    if (t.kind === "word" && (t.value === "current_setting" || t.value === "current_user" || t.value === "session_user")) identity = true;
  });
  if (mention.length === 0) return false;
  if (identity) return true;
  // column passed as an argument: name ( ... column ... ) where name is a function
  return mention.some((at) => {
    let depth = 0;
    for (let i = at - 1; i >= 0; i--) {
      const t = expr[i]!;
      if (t.text === ")") depth++;
      else if (t.text === "(") {
        if (depth === 0) {
          const before = expr[i - 1];
          return before !== undefined && (before.kind === "word" || before.kind === "qident") && !NOT_A_FUNCTION.has(before.value);
        }
        depth--;
      }
    }
    return false;
  });
}
