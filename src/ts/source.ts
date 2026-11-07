import ts from "typescript";
import { BudgetError, DEFAULT_LIMITS, tick, withBudget, type Limits } from "../limits.js";
import { evidenceLine } from "../redact.js";
import type { Project, Site } from "../types.js";

export type FunctionLike = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

export type EntryKind = "route" | "action" | "pages-api" | "page";

export interface Entry {
  kind: EntryKind;
  /** HTTP verb, action name or `handler`. */
  name: string;
  fn: FunctionLike;
  /** Node whose line is used when reporting on the entry (the declaration). */
  decl: ts.Node;
  /** Callee names of higher-order wrappers, e.g. `withAuth` in `export const POST = withAuth(async () => {})`. */
  wrappers: string[];
}

export interface SourceInfo {
  path: string;
  text: string;
  sf: ts.SourceFile;
  /** File starts with the "use client" directive. */
  isClient: boolean;
  /** File starts with the "use server" directive. */
  isServerActionFile: boolean;
  isAppRoute: boolean;
  isPagesApi: boolean;
  isAppPage: boolean;
  entries: Entry[];
}

const HTTP_METHODS: Record<string, true> = { GET: true, HEAD: true, POST: true, PUT: true, PATCH: true, DELETE: true, OPTIONS: true };
const SCRIPT_EXT = /\.(?:[cm]?[jt]sx?)$/;

export function isSourcePath(path: string): boolean {
  return SCRIPT_EXT.test(path) && !/\.d\.[cm]?ts$/.test(path);
}

function scriptKind(path: string): ts.ScriptKind {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/.test(path)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/** Directive prologue strings ("use client", "use server") of a block or file. */
function directives(statements: readonly ts.Statement[]): string[] {
  const out: string[] = [];
  for (const s of statements) {
    if (ts.isExpressionStatement(s) && ts.isStringLiteral(s.expression)) out.push(s.expression.text);
    else break;
  }
  return out;
}

export function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

const evidenceCache = new WeakMap<ts.SourceFile, Map<number, string>>();

/** A source line as evidence: trimmed, scrubbed of credential-shaped substrings, truncated. */
export function lineText(sf: ts.SourceFile, line: number, max = 180): string {
  let perFile = evidenceCache.get(sf);
  if (!perFile) {
    perFile = new Map();
    evidenceCache.set(sf, perFile);
  }
  const key = line * 1000 + max;
  let out = perFile.get(key);
  if (out === undefined) {
    const starts = sf.getLineStarts();
    const from = starts[line - 1] ?? 0;
    const to = starts[line] ?? sf.text.length;
    out = evidenceLine(sf.text.slice(from, to), max);
    perFile.set(key, out);
  }
  return out;
}

/** Short name of an entry point for titles and finding identity: "POST handler", "Server action save". */
export function entryLabel(entry: Entry): string {
  if (entry.kind === "route") return `${entry.name} handler`;
  if (entry.kind === "action") return `Server action ${entry.name}`;
  if (entry.kind === "page") return "Page component";
  return "API handler";
}

/** An entry point as a place in the project: where a request or a form post enters the code. */
export function entrySite(src: SourceInfo, entry: Entry): Site {
  const line = lineOf(src.sf, entry.decl);
  const note =
    entry.kind === "action"
      ? `${entryLabel(entry)} is exposed by Next.js as a public POST endpoint`
      : `${entryLabel(entry)} is reachable by anyone who can send a request to its URL`;
  return { file: src.path, line, note, text: lineText(src.sf, line) };
}

export function unwrap(node: ts.Node): ts.Node {
  let n = node;
  while (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression(n) || ts.isTypeAssertionExpression(n) || ts.isAwaitExpression(n)) n = n.expression;
  return n;
}

function isFunctionLike(n: ts.Node): n is FunctionLike {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n);
}

export { isFunctionLike };

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((m) => m.kind === kind) ?? false);
}

/** Resolves `fn`, `withAuth(fn)` and `withAuth(opts)(fn)` to the inner function and the wrapper names. */
function resolveFunction(expr: ts.Node, depth = 0): { fn: FunctionLike; wrappers: string[] } | null {
  const cur = unwrap(expr);
  if (isFunctionLike(cur)) return { fn: cur, wrappers: [] };
  if (!ts.isCallExpression(cur) || depth > 4) return null;
  const name = calleeName(cur.expression);
  for (const arg of cur.arguments) {
    const inner = resolveFunction(arg, depth + 1);
    if (inner) return { fn: inner.fn, wrappers: [name, ...inner.wrappers] };
  }
  return null;
}

export function calleeName(expr: ts.Expression): string {
  const e = unwrap(expr);
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  if (ts.isCallExpression(e)) return calleeName(e.expression);
  return "";
}

function collectEntries(sf: ts.SourceFile, info: Pick<SourceInfo, "isAppRoute" | "isPagesApi" | "isAppPage" | "isServerActionFile">): Entry[] {
  const entries: Entry[] = [];
  const seen = new Set<ts.Node>();
  const add = (kind: EntryKind, name: string, fn: FunctionLike, decl: ts.Node, wrappers: string[]): void => {
    if (seen.has(fn)) return;
    seen.add(fn);
    entries.push({ kind, name, fn, decl, wrappers });
  };

  for (const stmt of sf.statements) {
    const exported = hasModifier(stmt, ts.SyntaxKind.ExportKeyword);
    const isDefault = hasModifier(stmt, ts.SyntaxKind.DefaultKeyword);

    if (ts.isFunctionDeclaration(stmt) && exported) {
      const name = isDefault ? "default" : (stmt.name?.text ?? "default");
      if (info.isAppRoute && HTTP_METHODS[name] === true) add("route", name, stmt, stmt, []);
      else if (info.isPagesApi && isDefault) add("pages-api", stmt.name?.text ?? "handler", stmt, stmt, []);
      else if (info.isAppPage && isDefault) add("page", stmt.name?.text ?? "default", stmt, stmt, []);
      else if (info.isServerActionFile) add("action", name, stmt, stmt, []);
    } else if (ts.isVariableStatement(stmt) && exported) {
      for (const decl of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
        const resolved = resolveFunction(decl.initializer);
        if (!resolved) continue;
        const name = decl.name.text;
        if (info.isAppRoute && HTTP_METHODS[name] === true) add("route", name, resolved.fn, decl, resolved.wrappers);
        else if (info.isServerActionFile) add("action", name, resolved.fn, decl, resolved.wrappers);
      }
    } else if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      const resolved = resolveFunction(stmt.expression);
      if (!resolved) continue;
      if (info.isPagesApi) add("pages-api", "handler", resolved.fn, stmt, resolved.wrappers);
      else if (info.isAppPage) add("page", "default", resolved.fn, stmt, resolved.wrappers);
      else if (info.isServerActionFile) add("action", "default", resolved.fn, stmt, resolved.wrappers);
    }
  }

  // inline "use server" functions inside other files
  const visit = (node: ts.Node): void => {
    if (isFunctionLike(node) && node.body && ts.isBlock(node.body) && directives(node.body.statements).includes("use server")) {
      const name = node.name && ts.isIdentifier(node.name) ? node.name.text : "inline action";
      add("action", name, node, node, []);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return entries;
}

export class TooDeepError extends Error {
  override name = "TooDeepError";
}

/** Depth of the syntax tree, computed without recursion. Stops counting once it passes `limit`. */
function treeDepth(root: ts.Node, limit: number): number {
  let max = 0;
  const stack: { node: ts.Node; depth: number }[] = [{ node: root, depth: 1 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (depth > max) max = depth;
    if (max > limit) return max;
    ts.forEachChild(node, (child) => {
      stack.push({ node: child, depth: depth + 1 });
    });
  }
  return max;
}

export function parseSource(path: string, text: string, maxDepth = DEFAULT_LIMITS.maxAstDepth): SourceInfo {
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true, scriptKind(path));
  const depth = treeDepth(sf, maxDepth);
  if (depth > maxDepth) throw new TooDeepError(`not analysed: syntax tree nests deeper than ${maxDepth} levels`);
  const prologue = directives(sf.statements);
  const segments = path.split("/");
  const dirs = segments.slice(0, -1);
  const base = segments[segments.length - 1] ?? "";
  const pagesAt = dirs.indexOf("pages");
  const isAppRoute = /^route\.[cm]?[jt]sx?$/.test(base) && dirs.includes("app");
  const isPagesApi = pagesAt !== -1 && dirs[pagesAt + 1] === "api";
  const isAppPage = /^(?:page|layout)\.[jt]sx?$/.test(base) && dirs.includes("app");
  const isServerActionFile = prologue.includes("use server");
  const isClient = prologue.includes("use client");
  const entries = collectEntries(sf, { isAppRoute, isPagesApi, isAppPage, isServerActionFile });
  return { path, text, sf, isClient, isServerActionFile, isAppRoute, isPagesApi, isAppPage, entries };
}

/** Parses every JS/TS file in the project, in path order. Files that cannot be parsed are recorded in `skipped`. */
export function parseProject(project: Project, limits: Limits, skipped: string[]): SourceInfo[] {
  const out: SourceInfo[] = [];
  for (const [path, text] of project.files) {
    if (!isSourcePath(path)) continue;
    try {
      out.push(withBudget(limits.fileBudgetMs, () => parseSource(path, text, limits.maxAstDepth)));
    } catch (error) {
      skipped.push(`${path}: ${describeParseFailure(error)}`);
    }
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function describeParseFailure(error: unknown): string {
  if (error instanceof TooDeepError) return error.message;
  if (error instanceof BudgetError) return "not analysed: parsing exceeded the time budget";
  if (error instanceof RangeError) return "not analysed: syntax tree nests too deeply to parse";
  return `not analysed: parse failed (${error instanceof Error ? error.name : "error"})`;
}

/** All descendants of `node` (inclusive) satisfying the guard, in source order. */
export function findAll<T extends ts.Node>(node: ts.Node, guard: (n: ts.Node) => n is T): T[] {
  const out: T[] = [];
  const visit = (n: ts.Node): void => {
    tick();
    if (guard(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(node);
  return out;
}
