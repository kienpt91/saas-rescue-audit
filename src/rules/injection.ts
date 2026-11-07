import ts from "typescript";
import { tick } from "../limits.js";
import { calleeName, entryLabel, entrySite, findAll, lineOf, lineText, unwrap, type Entry, type SourceInfo } from "../ts/source.js";
import { computeTaint, isTainted, seedNames } from "../ts/taint.js";
import type { RawFinding } from "../types.js";
import type { Rule } from "./context.js";

const SANITIZER = /^(?:sanitize|sanitizeHtml|sanitizeHTML|purify|xss|escapeHtml|escapeHTML|cleanHtml)$/;
const GUARD_CALL = /^(?:startsWith|includes|test|has|indexOf|match|matches)$/;
const GUARD_HELPER = /safe|valid|allow|sanitiz|internal|relative|same.?origin|whitelist/i;

function constantStrings(sf: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  for (const d of findAll(sf, (n): n is ts.VariableDeclaration => ts.isVariableDeclaration(n))) {
    const list = d.parent;
    if (ts.isIdentifier(d.name) && d.initializer && ts.isVariableDeclarationList(list) && (list.flags & ts.NodeFlags.Const) !== 0) {
      const init = unwrap(d.initializer);
      if (ts.isStringLiteral(init) || ts.isNoSubstitutionTemplateLiteral(init)) out.add(d.name.text);
    }
  }
  return out;
}

type HtmlVerdict = "constant" | "sanitized" | "json" | "unsafe";

function judgeHtml(expr: ts.Node, constants: ReadonlySet<string>, sanitizers: ReadonlySet<string>): HtmlVerdict {
  const e = unwrap(expr);
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return "constant";
  if (ts.isIdentifier(e) && constants.has(e.text)) return "constant";
  if (ts.isCallExpression(e)) {
    const name = calleeName(e.expression);
    if (SANITIZER.test(name) || sanitizers.has(name)) return "sanitized";
    if (name === "stringify" && ts.isPropertyAccessExpression(e.expression) && ts.isIdentifier(e.expression.expression) && e.expression.expression.text === "JSON") return "json";
  }
  if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = judgeHtml(e.left, constants, sanitizers);
    const r = judgeHtml(e.right, constants, sanitizers);
    if (l === "constant" && r === "constant") return "constant";
  }
  return "unsafe";
}

function htmlFindings(src: SourceInfo, sanitizers: ReadonlySet<string>, out: RawFinding[]): void {
  const { sf, path } = src;
  const constants = constantStrings(sf);
  const report = (node: ts.Node, verdict: HtmlVerdict, what: string): void => {
    if (verdict === "constant" || verdict === "sanitized") return;
    const line = lineOf(sf, node);
    if (verdict === "json") {
      out.push({
        rule: "unsafe-html",
        severity: "low",
        file: path,
        line,
        title: `${what} receives JSON.stringify output`,
        message: 'JSON.stringify does not escape "<", so a string value containing "</script>" ends the script element early and the rest is parsed as HTML.',
        evidence: lineText(sf, line),
        fix: 'Escape the output before injecting it: JSON.stringify(data).replace(/</g, "\\\\u003c").',
      });
      return;
    }
    out.push({
      rule: "unsafe-html",
      severity: "high",
      file: path,
      line,
      title: `${what} receives non-constant input`,
      message: "Anything that reaches this sink is parsed as HTML in the visitor's browser. If any part of it comes from a user, a database row or a third-party API, that is stored or reflected cross-site scripting, and an XSS bug can read the session and call every API as the user.",
      evidence: lineText(sf, line),
      fix: "Render the value as text (JSX escapes it). If HTML is required, sanitize it on the server with an allow-list sanitizer first and pass the result, or render Markdown with raw HTML disabled.",
    });
  };

  const visit = (n: ts.Node): void => {
    if (ts.isJsxAttribute(n) && ts.isIdentifier(n.name) && n.name.text === "dangerouslySetInnerHTML") {
      const init = n.initializer;
      const expr = init && ts.isJsxExpression(init) ? init.expression : undefined;
      const obj = expr ? unwrap(expr) : undefined;
      if (obj && ts.isObjectLiteralExpression(obj)) {
        const html = obj.properties.find((p): p is ts.PropertyAssignment | ts.ShorthandPropertyAssignment => (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && p.name.getText(sf) === "__html");
        if (html) report(n, judgeHtml(ts.isPropertyAssignment(html) ? html.initializer : html.name, constants, sanitizers), "dangerouslySetInnerHTML");
        else report(n, "unsafe", "dangerouslySetInnerHTML");
      } else report(n, "unsafe", "dangerouslySetInnerHTML");
    } else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left) && /^(?:innerHTML|outerHTML)$/.test(n.left.name.text)) {
      report(n, judgeHtml(n.right, constants, sanitizers), `${n.left.name.text} assignment`);
    } else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const name = n.expression.name.text;
      if (name === "insertAdjacentHTML" && n.arguments[1]) report(n, judgeHtml(n.arguments[1], constants, sanitizers), "insertAdjacentHTML");
      else if (name === "write" && ts.isIdentifier(n.expression.expression) && n.expression.expression.text === "document" && n.arguments[0]) report(n, judgeHtml(n.arguments[0], constants, sanitizers), "document.write");
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}

/** Splits `a + b` and template literals into text and expression parts, left to right. */
function parts(expr: ts.Node): { text?: string; expr?: ts.Node }[] {
  const e = unwrap(expr);
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return [{ text: e.text }];
  if (ts.isTemplateExpression(e)) {
    const out: { text?: string; expr?: ts.Node }[] = [{ text: e.head.text }];
    for (const span of e.templateSpans) out.push({ expr: span.expression }, { text: span.literal.text });
    return out;
  }
  if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) return [...parts(e.left), ...parts(e.right)];
  return [{ expr: e }];
}

/** The scheme and host are fixed by the server: a path prefix, a literal host, or an untainted base followed by "/". */
function hostIsFixed(arg: ts.Node, tainted: ReadonlySet<string>): boolean {
  const ps = parts(arg).filter((p) => p.text !== "");
  const first = ps[0];
  if (!first) return false;
  if (first.text !== undefined) return (first.text.startsWith("/") && !first.text.startsWith("//")) || /^https?:\/\/[^/]+(?:\/|$)/.test(first.text) || (/^https?:\/\/[^/]*$/.test(first.text) && ps.length === 1);
  const second = ps[1];
  return first.expr !== undefined && !isTainted(first.expr, tainted) && second?.text !== undefined && second.text.startsWith("/");
}

function identifiersIn(node: ts.Node): string[] {
  return findAll(node, (n): n is ts.Identifier => ts.isIdentifier(n)).map((i) => i.text);
}

interface ScopeIndex {
  calls: ts.CallExpression[];
  binaries: ts.BinaryExpression[];
  declarations: ts.VariableDeclaration[];
  identifiers: Map<string, ts.Identifier[]>;
}

const scopeCache = new WeakMap<ts.Node, ScopeIndex>();

/** One pass over a scope, so every redirect in it shares the same lists. */
function indexScope(scope: ts.Node): ScopeIndex {
  let index = scopeCache.get(scope);
  if (index) return index;
  index = { calls: [], binaries: [], declarations: [], identifiers: new Map() };
  for (const n of findAll(scope, (x): x is ts.Node => true)) {
    if (ts.isCallExpression(n)) index.calls.push(n);
    else if (ts.isBinaryExpression(n)) index.binaries.push(n);
    else if (ts.isVariableDeclaration(n) && n.initializer) index.declarations.push(n);
    else if (ts.isIdentifier(n)) {
      const list = index.identifiers.get(n.text) ?? [];
      list.push(n);
      index.identifiers.set(n.text, list);
    }
  }
  scopeCache.set(scope, index);
  return index;
}

/** Tainted names the sink argument depends on, following `const a = f(b)` chains back to their sources. */
function dependencyNames(index: ScopeIndex, arg: ts.Node, tainted: ReadonlySet<string>): Set<string> {
  const names = new Set(identifiersIn(arg).filter((n) => tainted.has(n)));
  for (let pass = 0; pass < 8; pass++) {
    const before = names.size;
    for (const d of index.declarations) {
      tick();
      if (!ts.isIdentifier(d.name) || !names.has(d.name.text) || !d.initializer) continue;
      for (const id of identifiersIn(d.initializer)) if (tainted.has(id)) names.add(id);
    }
    if (names.size === before) break;
  }
  return names;
}

/**
 * Whether the value of `node` decides which way the code goes: it is (part of) the condition of an if,
 * a loop or a ternary, or it is returned from a helper, or it is stored in a variable that is used that way.
 * A check whose result is thrown away guards nothing.
 */
function usedAsCondition(node: ts.Node, index: ScopeIndex, depth = 0): boolean {
  let child: ts.Node = node;
  for (let p: ts.Node | undefined = node.parent; p; child = p, p = p.parent) {
    if (ts.isParenthesizedExpression(p) || ts.isAwaitExpression(p) || (ts.isPrefixUnaryExpression(p) && p.operator === ts.SyntaxKind.ExclamationToken)) continue;
    if (ts.isBinaryExpression(p) && (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken || p.operatorToken.kind === ts.SyntaxKind.BarBarToken || p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) continue;
    if (ts.isIfStatement(p) || ts.isWhileStatement(p)) return p.expression === child;
    if (ts.isConditionalExpression(p)) return p.condition === child;
    if (ts.isReturnStatement(p) || ts.isArrowFunction(p)) return true;
    if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name) && depth < 2) {
      const name = p.name;
      return (index.identifiers.get(name.text) ?? []).some((id) => id !== name && usedAsCondition(id, index, depth + 1));
    }
    return false;
  }
  return false;
}

/** A check on the redirect target (startsWith, an allow-list lookup, an equality test) that is used as a condition before the sink. */
function guarded(scope: ts.Node, arg: ts.Node, tainted: ReadonlySet<string>, sinkStart: number): boolean {
  // a direct reference: `next`, `next.length`, `url.origin`, but not `searchParams.get("type")`
  const isRef = (node: ts.Node, name: string): boolean => {
    const e = unwrap(node);
    if (ts.isIdentifier(e)) return e.text === name;
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) return isRef(e.expression, name);
    return false;
  };
  const compares: ts.SyntaxKind[] = [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken];
  const index = indexScope(scope);
  for (const name of dependencyNames(index, arg, tainted)) {
    for (const call of index.calls) {
      tick();
      if (call.getStart() >= sinkStart) break;
      const callee = call.expression;
      const cname = calleeName(callee);
      const matches =
        (GUARD_CALL.test(cname) && (call.arguments.some((a) => isRef(a, name)) || (/^(?:startsWith|includes|match|matches|indexOf)$/.test(cname) && ts.isPropertyAccessExpression(callee) && isRef(callee.expression, name)))) ||
        (GUARD_HELPER.test(cname) && call.arguments.some((a) => isRef(a, name)));
      if (matches && usedAsCondition(call, index)) return true;
    }
    for (const bin of index.binaries) {
      tick();
      if (bin.getStart() >= sinkStart) break;
      if (compares.includes(bin.operatorToken.kind) && (isRef(bin.left, name) || isRef(bin.right, name)) && usedAsCondition(bin, index)) return true;
    }
  }
  return false;
}

/** Last name of an identifier or property access, without printing the expression. */
function tailName(e: ts.Node): string {
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  return "";
}

function redirectTarget(n: ts.Node): ts.Node | null {
  if (ts.isCallExpression(n)) {
    const callee = n.expression;
    const name = calleeName(callee);
    const receiver = ts.isPropertyAccessExpression(callee) ? tailName(callee.expression) : "";
    if (ts.isIdentifier(callee) && /^(?:redirect|permanentRedirect)$/.test(name)) return n.arguments[0] ?? null;
    if (ts.isPropertyAccessExpression(callee) && name === "redirect" && /^(?:NextResponse|Response|res|response)$/.test(receiver)) return n.arguments[n.arguments.length - 1] ?? null;
    if (ts.isPropertyAccessExpression(callee) && /^(?:push|replace)$/.test(name) && /router$/i.test(receiver)) return n.arguments[0] ?? null;
    if (ts.isPropertyAccessExpression(callee) && /^(?:assign|replace)$/.test(name) && receiver === "location") return n.arguments[0] ?? null;
  } else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left)) {
    const left = n.left;
    if (left.name.text === "location" || (left.name.text === "href" && tailName(left.expression) === "location")) return n.right;
  }
  return null;
}

function redirectFindings(src: SourceInfo, out: RawFinding[]): void {
  const scopes: { root: ts.Node; tainted: Set<string>; entry?: Entry }[] = src.entries.map((e) => ({ root: e.fn, tainted: computeTaint(e.fn.body, seedNames(e)), entry: e }));
  if (src.isClient) scopes.push({ root: src.sf, tainted: computeTaint(src.sf, []) });
  const seen = new Set<ts.Node>();
  for (const { root, tainted, entry } of scopes) {
    for (const node of findAll(root, (n): n is ts.Node => true)) {
      const arg = redirectTarget(node);
      if (!arg || seen.has(node) || !isTainted(arg, tainted)) continue;
      seen.add(node);
      if (hostIsFixed(arg, tainted) || guarded(root, arg, tainted, node.getStart())) continue;
      const line = lineOf(src.sf, node);
      out.push({
        rule: "open-redirect",
        severity: "medium",
        file: src.path,
        line,
        title: "Redirect target comes from the request",
        message: 'A crafted link such as /login?next=https://evil.example sends a user who just authenticated to an attacker-controlled page that looks like yours. Prefixing the origin does not help on its own: "https://app.example" + "@evil.example" or "//evil.example" still changes the destination.',
        evidence: lineText(src.sf, line),
        fix: 'Only accept relative paths: check value.startsWith("/") && !value.startsWith("//") && !value.includes("\\\\"), or map a short key to a fixed list of destinations, and fall back to "/" otherwise.',
        subject: [entry ? entryLabel(entry) : "Client code"],
        ...(entry ? { entry: entrySite(src, entry) } : {}),
      });
    }
  }
}

export const injectionRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  const sanitizers = new Set(ctx.config.sanitizers);
  for (const src of ctx.sources) {
    ctx.guard(src.path, () => {
      htmlFindings(src, sanitizers, out);
      redirectFindings(src, out);
    });
  }
  return out;
};
