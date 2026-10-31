import ts from "typescript";
import type { Project } from "../types.js";

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

export function lineText(sf: ts.SourceFile, line: number, max = 180): string {
  const starts = sf.getLineStarts();
  const from = starts[line - 1] ?? 0;
  const to = starts[line] ?? sf.text.length;
  const text = sf.text.slice(from, to).replace(/\s+$/, "").trim();
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
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

export function parseSource(path: string, text: string): SourceInfo {
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true, scriptKind(path));
  const prologue = directives(sf.statements);
  const isAppRoute = /(?:^|\/)app\/(?:.+\/)?route\.[cm]?[jt]sx?$/.test(path);
  const isPagesApi = /(?:^|\/)pages\/api\//.test(path);
  const isAppPage = /(?:^|\/)app\/(?:.+\/)?(?:page|layout)\.[jt]sx?$/.test(path);
  const isServerActionFile = prologue.includes("use server");
  const isClient = prologue.includes("use client");
  const entries = collectEntries(sf, { isAppRoute, isPagesApi, isAppPage, isServerActionFile });
  return { path, text, sf, isClient, isServerActionFile, isAppRoute, isPagesApi, isAppPage, entries };
}

/** Parses every JS/TS file in the project, in path order. */
export function parseProject(project: Project): SourceInfo[] {
  const out: SourceInfo[] = [];
  for (const [path, text] of project.files) {
    if (isSourcePath(path)) out.push(parseSource(path, text));
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** All descendants of `node` (inclusive) satisfying the guard, in source order. */
export function findAll<T extends ts.Node>(node: ts.Node, guard: (n: ts.Node) => n is T): T[] {
  const out: T[] = [];
  const visit = (n: ts.Node): void => {
    if (guard(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(node);
  return out;
}
