import ts from "typescript";
import { findDataOps } from "../ts/calls.js";
import { calleeName, findAll, lineOf, lineText, unwrap, type Entry, type SourceInfo } from "../ts/source.js";
import { computeTaint, isTainted, seedNames } from "../ts/taint.js";
import type { RawFinding } from "../types.js";
import type { Rule } from "./context.js";

const EVENT_TYPE_STRING = /^(?:checkout\.session|customer|customer\.subscription|invoice|payment_intent|payment_method|charge|price|product|setup_intent)(?:\.[a-z_]+)+$/;
const IDEMPOTENCY_NAME = /idempot|alreadyProcessed|isProcessed|markProcessed|wasProcessed|dedup/i;

export function isStripeWebhook(src: SourceInfo): boolean {
  if (!src.isAppRoute && !src.isPagesApi) return false;
  if (!/stripe/i.test(src.text)) return false;
  if (/webhook/i.test(src.path) || src.text.includes("stripe-signature") || /constructEvent(?:Async)?\b/.test(src.text)) return true;
  return findAll(src.sf, (n): n is ts.StringLiteral => ts.isStringLiteral(n)).some((s) => EVENT_TYPE_STRING.test(s.text));
}

function isParseCall(call: ts.CallExpression): boolean {
  const callee = unwrap(call.expression);
  if (ts.isPropertyAccessExpression(callee)) {
    if (callee.name.text === "json" && call.arguments.length === 0) return true;
    return ts.isIdentifier(callee.expression) && callee.expression.text === "JSON" && callee.name.text === "parse";
  }
  return false;
}

function enclosingFunction(node: ts.Node): ts.Node {
  let n: ts.Node | undefined = node.parent;
  while (n && !ts.isFunctionLike(n) && !ts.isSourceFile(n)) n = n.parent;
  return n ?? node;
}

/** Name the call result is stored in: `const event = f()` or `event = f()`. */
function boundName(call: ts.CallExpression): string | null {
  let p: ts.Node = call.parent;
  while (ts.isAwaitExpression(p) || ts.isParenthesizedExpression(p) || ts.isAsExpression(p) || ts.isNonNullExpression(p)) p = p.parent;
  if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(p.left)) return p.left.text;
  return null;
}
/** Numeric status >= 400 in a returned response expression, or null. */
function errorStatus(node: ts.Node): number | null {
  let found: number | null = null;
  const visit = (n: ts.Node): void => {
    if (found !== null) return;
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === "status" && ts.isNumericLiteral(n.initializer) && Number(n.initializer.text) >= 400) found = Number(n.initializer.text);
    else if (ts.isCallExpression(n) && /^(?:status|sendStatus)$/.test(calleeName(n.expression)) && n.arguments[0] && ts.isNumericLiteral(n.arguments[0]) && Number(n.arguments[0].text) >= 400) found = Number(n.arguments[0].text);
    else if (ts.isCallExpression(n) && n.arguments[1] && ts.isNumericLiteral(n.arguments[1]) && Number(n.arguments[1].text) >= 400 && /json/i.test(calleeName(n.expression))) found = Number(n.arguments[1].text);
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function failureIn(stmts: readonly ts.Statement[]): { node: ts.Node; what: string } | null {
  for (const s of stmts) {
    for (const inner of findAll(s, (n): n is ts.ReturnStatement | ts.ThrowStatement => ts.isReturnStatement(n) || ts.isThrowStatement(n))) {
      if (ts.isThrowStatement(inner)) return { node: inner, what: "throws" };
      const status = inner.expression ? errorStatus(inner.expression) : null;
      if (status !== null) return { node: inner, what: `returns ${status}` };
    }
  }
  return null;
}

function mentionsEventType(expr: ts.Node): boolean {
  return findAll(expr, (n): n is ts.PropertyAccessExpression => ts.isPropertyAccessExpression(n)).some((p) => p.name.text === "type");
}

function unknownEventFailure(sf: ts.SourceFile): { node: ts.Node; what: string } | null {
  let result: { node: ts.Node; what: string } | null = null;
  const visit = (n: ts.Node): void => {
    if (result) return;
    if (ts.isSwitchStatement(n) && mentionsEventType(n.expression)) {
      const def = n.caseBlock.clauses.find((c): c is ts.DefaultClause => ts.isDefaultClause(c));
      if (def) result = failureIn(def.statements);
    } else if (ts.isIfStatement(n) && mentionsEventType(n.expression) && !(ts.isIfStatement(n.parent) && n.parent.elseStatement === n)) {
      let last: ts.Statement | undefined = n;
      while (last && ts.isIfStatement(last) && last.elseStatement) last = last.elseStatement;
      if (last && last !== n && !ts.isIfStatement(last)) result = failureIn(ts.isBlock(last) ? last.statements : [last]);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return result;
}

function webhookFindings(src: SourceInfo, extraIdempotency: readonly string[], out: RawFinding[]): void {
  const { sf, path } = src;
  const handler = src.entries.find((e) => e.name === "POST") ?? src.entries[0];
  const handlerLine = handler ? lineOf(sf, handler.decl) : 1;
  const calls = findAll(sf, (n): n is ts.CallExpression => ts.isCallExpression(n));
  const verifications = calls.filter((c) => /^constructEvent(?:Async)?$/.test(calleeName(c.expression)));
  const parseCalls = calls.filter(isParseCall);

  if (verifications.length === 0) {
    const parse = parseCalls[0];
    out.push({
      rule: "stripe-webhook-unverified",
      severity: "critical",
      file: path,
      line: handlerLine,
      title: "Stripe webhook never verifies the signature",
      message: `Anyone who finds this URL can POST a forged checkout.session.completed or invoice.paid event and the handler will act on it${parse ? " (the body is parsed as JSON and trusted as is)" : ""}. Stripe signs every delivery precisely so that this is not possible.`,
      evidence: parse ? lineText(sf, lineOf(sf, parse)) : lineText(sf, handlerLine),
      fix: 'Read the raw body with "await request.text()", read the stripe-signature header and call stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET) before using any field. Return 400 on failure.',
    });
  } else {
    const first = verifications[0]!;
    const scope = enclosingFunction(first);
    const firstArg = first.arguments[0] ? unwrap(first.arguments[0]) : null;
    const earlier = parseCalls.find((c) => c.getStart(sf) < first.getStart(sf) && enclosingFunction(c) === scope);
    const restringified = firstArg !== null && ts.isCallExpression(firstArg) && /^stringify$/.test(calleeName(firstArg.expression));
    const pagesBody = src.isPagesApi && firstArg !== null && ts.isPropertyAccessExpression(firstArg) && firstArg.name.text === "body";
    const bodyParserOff = /bodyParser\s*:\s*false/.test(src.text);
    if (earlier || restringified || (pagesBody && !bodyParserOff)) {
      const node = earlier ?? first;
      const line = lineOf(sf, node);
      out.push({
        rule: "stripe-webhook-parse-before-verify",
        severity: "high",
        file: path,
        line,
        title: "Request body is parsed before the signature is verified",
        message: "The signature covers the exact bytes Stripe sent. Parsing the body first and re-serialising it changes those bytes, so verification fails in production. The usual workaround, trusting the parsed body and dropping verification, removes the protection altogether.",
        evidence: lineText(sf, line),
        fix: pagesBody ? 'Export config = { api: { bodyParser: false } }, read the raw buffer from the request stream, and pass that to constructEvent.' : 'Use "const rawBody = await request.text()" and pass rawBody to constructEvent; parse JSON only from the verified event.',
      });
    }

    // idempotency: does the handler read event.id at all?
    const eventName = boundName(first);
    const usesId = eventName !== null && findAll(sf, (n): n is ts.PropertyAccessExpression => ts.isPropertyAccessExpression(n)).some((p) => ts.isIdentifier(p.expression) && p.expression.text === eventName && p.name.text === "id");
    const destructuresId = eventName !== null && findAll(sf, (n): n is ts.VariableDeclaration => ts.isVariableDeclaration(n)).some((d) => d.initializer && ts.isIdentifier(d.initializer) && d.initializer.text === eventName && ts.isObjectBindingPattern(d.name) && d.name.elements.some((el) => ts.isIdentifier(el.name) && (el.propertyName ? ts.isIdentifier(el.propertyName) && el.propertyName.text === "id" : el.name.text === "id")));
    const helper = calls.some((c) => IDEMPOTENCY_NAME.test(calleeName(c.expression)) || extraIdempotency.includes(calleeName(c.expression)));
    if (!usesId && !destructuresId && !helper) {
      const line = lineOf(sf, first);
      out.push({
        rule: "stripe-webhook-no-idempotency",
        severity: "medium",
        file: path,
        line,
        title: "Webhook does not deduplicate events",
        message: "Stripe delivers events at least once and retries on any non-2xx answer, so the same event can arrive twice. Without a stored event.id, fulfilment code (credits, emails, plan changes) runs twice.",
        evidence: lineText(sf, line),
        fix: "Insert event.id into a table with a unique constraint before doing the work (on conflict do nothing) and return 200 early when the row already existed. Do the insert and the work in one transaction.",
      });
    }
  }

  const unknown = unknownEventFailure(sf);
  if (unknown) {
    const line = lineOf(sf, unknown.node);
    out.push({
      rule: "stripe-webhook-unknown-event-error",
      severity: "low",
      file: path,
      line,
      title: `Unhandled event types make the handler fail (${unknown.what})`,
      message: "Stripe sends every event type the endpoint is subscribed to. A non-2xx answer for an event you simply do not handle is retried for days and, after repeated failures, the endpoint is disabled, which then also drops the events you do care about.",
      evidence: lineText(sf, line),
      fix: "Return 200 for unhandled types (log them) and reserve error statuses for events you tried to process and failed. Subscribe the endpoint only to the events you handle.",
    });
  }
}

/** Stripe calls where client input must not decide money or whose object is touched. */
function checkoutFindings(src: SourceInfo, entry: Entry, extraRoots: readonly string[], out: RawFinding[]): void {
  const { sf, path } = src;
  const tainted = computeTaint(entry.fn, seedNames(entry));
  for (const op of findDataOps(entry.fn, extraRoots)) {
    if (op.via !== "stripe") continue;
    const link = op.chain.links[op.chain.links.length - 1]!;
    const arg0 = link.args[0] ? unwrap(link.args[0]) : null;
    const createsMoney = (op.target === "checkout" || op.target === "paymentIntents" || op.target === "subscriptions" || op.target === "invoiceItems" || op.target === "paymentLinks") && op.method === "create";

    if (createsMoney && arg0 && ts.isObjectLiteralExpression(arg0)) {
      const found: { amount?: ts.Node; price?: ts.Node } = {};
      const visit = (n: ts.Node): void => {
        if (ts.isPropertyAssignment(n) || ts.isShorthandPropertyAssignment(n)) {
          const key = ts.isIdentifier(n.name) || ts.isStringLiteral(n.name) ? n.name.text : "";
          const value = ts.isPropertyAssignment(n) ? n.initializer : n.name;
          const direct = unwrap(value);
          const wholesale = /^(?:line_items|items)$/.test(key) && (ts.isIdentifier(direct) || ts.isPropertyAccessExpression(direct) || ts.isElementAccessExpression(direct));
          if ((wholesale || /^(?:unit_amount|unit_amount_decimal|amount)$/.test(key)) && isTainted(value, tainted)) found.amount ??= n;
          else if (key === "price" && isTainted(value, tainted)) found.price ??= n;
        }
        ts.forEachChild(n, visit);
      };
      visit(arg0);
      if (found.amount) {
        const l = lineOf(sf, found.amount);
        out.push({
          rule: "stripe-checkout-client-price",
          severity: "high",
          file: path,
          line: l,
          title: "Amount or line items come from the request",
          message: "The client decides what it pays: a request with a smaller amount or a hand-written cart creates a valid payment for less. Anything the browser sends can be edited.",
          evidence: lineText(sf, l),
          fix: "Accept only a plan or product key from the client, look the price up server-side (a map of allowed Stripe price ids or a database row), and build line_items from that.",
        });
      } else if (found.price) {
        const l = lineOf(sf, found.price);
        out.push({
          rule: "stripe-checkout-client-price",
          severity: "medium",
          file: path,
          line: l,
          title: "Price id comes from the request without an allow-list",
          message: "A caller can pass any price id that exists in the Stripe account, including archived, internal or discounted prices.",
          evidence: lineText(sf, l),
          fix: "Map a plan key sent by the client to a price id held on the server, and reject keys that are not in the map.",
        });
      }
    }

    // object ids that must belong to the caller
    let unchecked: ts.Node | null = null;
    if (/^(?:customers|subscriptions|invoices|paymentMethods)$/.test(op.target) && /^(?:retrieve|update|del|cancel|detach|attach|list|search)$/.test(op.method) && arg0 && isTainted(arg0, tainted)) unchecked = arg0;
    else if (/^(?:billingPortal|checkout|paymentIntents|setupIntents|subscriptions|refunds)$/.test(op.target) && op.method === "create" && arg0 && ts.isObjectLiteralExpression(arg0)) {
      for (const p of arg0.properties) {
        const key = (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && ts.isIdentifier(p.name) ? p.name.text : "";
        const value = ts.isPropertyAssignment(p) ? p.initializer : ts.isShorthandPropertyAssignment(p) ? p.name : null;
        if (value && /^(?:customer|subscription|payment_intent|charge)$/.test(key) && isTainted(value, tainted)) unchecked = p;
      }
    }
    if (unchecked) {
      const l = lineOf(sf, unchecked);
      out.push({
        rule: "stripe-customer-unchecked",
        severity: "high",
        file: path,
        line: l,
        title: `Stripe ${op.chain.links.map((link) => link.name).join(".")} uses an id from the request`,
        message: "Nothing ties the id to the signed-in user, so a caller can pass another customer's id and open their billing portal, read or cancel their subscription, or refund their payment.",
        evidence: lineText(sf, l),
        fix: "Resolve the customer from the authenticated user (a stripe_customer_id column looked up by session user id) and ignore any id in the request. If an id must be accepted, compare it to that stored value first.",
      });
    }
  }
}

export const stripeRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  for (const src of ctx.sources) {
    if (src.isClient) continue;
    if (isStripeWebhook(src)) webhookFindings(src, ctx.config.idempotencyHelpers, out);
    for (const entry of src.entries) {
      if (entry.kind === "page") continue;
      checkoutFindings(src, entry, ctx.config.dataAccessRoots, out);
    }
  }
  return out;
};
