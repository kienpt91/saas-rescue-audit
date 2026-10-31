/**
 * Intra-function taint tracking for client-controlled input. It is deliberately
 * simple: names are not scoped, and values that pass through any function that is
 * not on the pass-through list (a database lookup, an allow-list helper) are
 * treated as no longer client-controlled.
 */
import ts from "typescript";
import { calleeName, isFunctionLike, type Entry } from "./source.js";

const PASS_THROUGH: Record<string, true> = {
  Number: true,
  String: true,
  parseInt: true,
  parseFloat: true,
  BigInt: true,
  Boolean: true,
  decodeURIComponent: true,
  decodeURI: true,
  parse: true,
  safeParse: true,
  round: true,
  floor: true,
  ceil: true,
  trunc: true,
  abs: true,
  min: true,
  max: true,
  fromEntries: true,
  assign: true,
};

const PASS_THROUGH_CONSTRUCTORS: Record<string, true> = { URL: true, URLSearchParams: true, Request: true };

const TAINTING_OPERATORS: Partial<Record<ts.SyntaxKind, true>> = {
  [ts.SyntaxKind.PlusToken]: true,
  [ts.SyntaxKind.MinusToken]: true,
  [ts.SyntaxKind.AsteriskToken]: true,
  [ts.SyntaxKind.SlashToken]: true,
  [ts.SyntaxKind.PercentToken]: true,
  [ts.SyntaxKind.AsteriskAsteriskToken]: true,
  [ts.SyntaxKind.QuestionQuestionToken]: true,
  [ts.SyntaxKind.BarBarToken]: true,
  [ts.SyntaxKind.AmpersandAmpersandToken]: true,
  [ts.SyntaxKind.CommaToken]: true,
};

/** Parts of a URL the server fixes (the request's own origin), which are not treated as attacker-chosen. */
const NON_USER_PROPS: Record<string, true> = { origin: true, host: true, hostname: true, protocol: true, port: true };

export function bindingNames(name: ts.BindingName, out: string[] = []): string[] {
  if (ts.isIdentifier(name)) out.push(name.text);
  else {
    for (const el of name.elements) {
      if (!ts.isBindingElement(el)) continue;
      const key = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : "";
      if (NON_USER_PROPS[key] !== true) bindingNames(el.name, out);
    }
  }
  return out;
}

export function isTainted(node: ts.Node, tainted: ReadonlySet<string>): boolean {
  if (ts.isIdentifier(node)) return tainted.has(node.text);
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node) || ts.isAwaitExpression(node) || ts.isSpreadElement(node)) {
    return isTainted(node.expression, tainted);
  }
  if (ts.isPropertyAccessExpression(node)) {
    if (NON_USER_PROPS[node.name.text] === true) return false;
    // window.location.search and location.hash carry attacker-chosen text
    if (/^(?:search|hash)$/.test(node.name.text) && /location$/.test(node.expression.getText())) return true;
    return isTainted(node.expression, tainted);
  }
  if (ts.isElementAccessExpression(node)) return isTainted(node.expression, tainted);
  if (ts.isCallExpression(node)) {
    const callee = node.expression;
    if (/^(?:useSearchParams|useParams)$/.test(calleeName(callee))) return true;
    if (ts.isPropertyAccessExpression(callee) && isTainted(callee.expression, tainted)) return true;
    if (PASS_THROUGH[calleeName(callee)] === true) return node.arguments.some((a) => isTainted(a, tainted));
    return false;
  }
  if (ts.isNewExpression(node)) {
    const name = ts.isIdentifier(node.expression) ? node.expression.text : "";
    const args = node.arguments ?? [];
    // new URL(path, base): the destination is decided by the first argument; a request URL as base only supplies the origin
    if (name === "URL") return args[0] !== undefined && isTainted(args[0], tainted);
    return PASS_THROUGH_CONSTRUCTORS[name] === true && args.some((a) => isTainted(a, tainted));
  }
  if (ts.isTemplateExpression(node)) return node.templateSpans.some((s) => isTainted(s.expression, tainted));
  if (ts.isBinaryExpression(node)) return TAINTING_OPERATORS[node.operatorToken.kind] === true && (isTainted(node.left, tainted) || isTainted(node.right, tainted));
  if (ts.isConditionalExpression(node)) return isTainted(node.whenTrue, tainted) || isTainted(node.whenFalse, tainted);
  if (ts.isPrefixUnaryExpression(node)) return (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken) && isTainted(node.operand, tainted);
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((p) => {
      if (ts.isPropertyAssignment(p)) return isTainted(p.initializer, tainted);
      if (ts.isShorthandPropertyAssignment(p)) return tainted.has(p.name.text);
      if (ts.isSpreadAssignment(p)) return isTainted(p.expression, tainted);
      return false;
    });
  }
  if (ts.isArrayLiteralExpression(node)) return node.elements.some((e) => isTainted(e, tainted));
  return false;
}

/** Names that carry client input at the start of an entry point: every parameter. */
export function seedNames(entry: Entry): string[] {
  const names: string[] = [];
  for (const p of entry.fn.parameters) bindingNames(p.name, names);
  return names;
}

/** Fixed-point propagation of taint through declarations, assignments and loops inside `body`. */
export function computeTaint(body: ts.Node | undefined, seeds: readonly string[]): Set<string> {
  const tainted = new Set<string>(seeds);
  if (!body) return tainted;
  for (let pass = 0; pass < 12; pass++) {
    const before = tainted.size;
    const visit = (n: ts.Node): void => {
      if (ts.isVariableDeclaration(n) && n.initializer && isTainted(n.initializer, tainted)) {
        bindingNames(n.name).forEach((name) => tainted.add(name));
      } else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && isTainted(n.right, tainted)) {
        tainted.add(n.left.text);
      } else if (ts.isForOfStatement(n) && ts.isVariableDeclarationList(n.initializer) && isTainted(n.expression, tainted)) {
        n.initializer.declarations.forEach((d) => bindingNames(d.name).forEach((name) => tainted.add(name)));
      } else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && isTainted(n.expression.expression, tainted)) {
        // callback parameters of items.map(item => ...) where items is tainted
        for (const arg of n.arguments) {
          if (isFunctionLike(arg)) arg.parameters.forEach((p) => bindingNames(p.name).forEach((name) => tainted.add(name)));
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(body);
    if (tainted.size === before) break;
  }
  return tainted;
}
