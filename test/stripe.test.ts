import { describe, expect, it } from "vitest";
import type { AuditResult } from "../src/types.js";
import { run } from "./helpers.js";

const WEBHOOK = "app/api/stripe/webhook/route.ts";

function stripeFindings(r: AuditResult): string[] {
  return r.findings
    .filter((f) => f.rule.startsWith("stripe-"))
    .map((f) => `${f.rule}:${f.line}`)
    .sort();
}

const lines = (...l: string[]): string => l.join("\n") + "\n";

const HEAD = 'import Stripe from "stripe";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);';

const GOOD = lines(
  HEAD,
  "export async function POST(request: Request) {",
  "  const rawBody = await request.text();",
  '  const signature = request.headers.get("stripe-signature")!;',
  "  let event: Stripe.Event;",
  "  try {",
  "    event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!);",
  "  } catch {",
  '    return new Response("invalid signature", { status: 400 });',
  "  }",
  "  if (await alreadyProcessed(event.id)) return new Response(null, { status: 200 });",
  "  switch (event.type) {",
  '    case "checkout.session.completed":',
  "      break;",
  "    default:",
  "      break;",
  "  }",
  "  return new Response(null, { status: 200 });",
  "}",
  "async function alreadyProcessed(id: string) { return id === ''; }",
);

describe("stripe-webhook-unverified", () => {
  it("flags a handler that never calls constructEvent, at the POST declaration", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const event = await request.json();", '  if (event.type === "checkout.session.completed") await fulfil(event.data.object);', "  return new Response(null, { status: 200 });", "}", "async function fulfil(x: unknown) { return x; }"),
    });
    const f = r.findings.find((x) => x.rule === "stripe-webhook-unverified")!;
    expect(f).toMatchObject({ severity: "critical", line: 3, file: WEBHOOK });
    expect(f.message).toContain("parsed as JSON");
    expect(f.evidence).toBe("const event = await request.json();");
  });

  it("detects a webhook by its stripe-signature header even when the path says nothing", () => {
    const r = run({ "app/api/hooks/in/route.ts": lines(HEAD, "export async function POST(req: Request) {", '  const sig = req.headers.get("stripe-signature");', "  return new Response(sig);", "}") });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-unverified:3"]);
  });

  it("does not treat other webhooks as Stripe webhooks", () => {
    const r = run({ "app/api/webhooks/github/route.ts": lines("export async function POST(req: Request) {", "  const body = await req.json();", "  return Response.json(body);", "}") });
    expect(stripeFindings(r)).toEqual([]);
  });

  it("accepts a correct handler", () => {
    expect(stripeFindings(run({ [WEBHOOK]: GOOD }))).toEqual([]);
  });

  it("reads the pages router default export too", () => {
    const r = run({ "pages/api/stripe-webhook.ts": lines(HEAD, "export default async function handler(req: NextApiRequest, res: NextApiResponse) {", "  const event = req.body;", "  res.status(200).json({ ok: event.id });", "}") });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-unverified:3"]);
  });
});

describe("stripe-webhook-parse-before-verify", () => {
  it("flags request.json() before constructEvent", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const body = await request.json();", '  const sig = request.headers.get("stripe-signature")!;', "  const event = stripe.webhooks.constructEvent(JSON.stringify(body), sig, process.env.STRIPE_WEBHOOK_SECRET!);", "  await markProcessed(event.id);", "  return new Response(null);", "}", "async function markProcessed(id: string) { return id; }"),
    });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-parse-before-verify:4"]);
    expect(r.findings.find((f) => f.rule === "stripe-webhook-parse-before-verify")!.evidence).toBe("const body = await request.json();");
  });

  it("flags a re-serialised first argument even when the parse happened elsewhere", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const parsed = await readBody(request);", "  const event = stripe.webhooks.constructEvent(JSON.stringify(parsed), 's', 'w');", "  await markProcessed(event.id);", "  return new Response(null);", "}", "declare function readBody(r: Request): Promise<unknown>;", "async function markProcessed(id: string) { return id; }"),
    });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-parse-before-verify:5"]);
  });

  it("does not flag parsing the verified event or parsing after verification", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const raw = await request.text();", "  const event = stripe.webhooks.constructEvent(raw, 's', 'w');", "  await markProcessed(event.id);", "  const meta = JSON.parse(event.data.object.metadata.payload);", "  return Response.json(meta);", "}", "async function markProcessed(id: string) { return id; }"),
    });
    expect(stripeFindings(r)).toEqual([]);
  });

  it("flags req.body in the pages router unless the body parser is disabled", () => {
    const base = lines(HEAD, "export default async function handler(req: NextApiRequest, res: NextApiResponse) {", "  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], 'w');", "  await markProcessed(event.id);", "  res.status(200).end();", "}", "async function markProcessed(id: string) { return id; }");
    const flagged = run({ "pages/api/stripe-webhook.ts": base });
    const fixed = run({ "pages/api/stripe-webhook.ts": base + "export const config = { api: { bodyParser: false } };\n" });
    expect(stripeFindings(flagged)).toEqual(["stripe-webhook-parse-before-verify:4"]);
    expect(stripeFindings(fixed)).toEqual([]);
  });
});

describe("stripe-webhook-no-idempotency", () => {
  const handler = (middle: string) =>
    lines(HEAD, "export async function POST(request: Request) {", "  const raw = await request.text();", "  const event = stripe.webhooks.constructEvent(raw, 's', 'w');", middle, "  return new Response(null);", "}", "async function record(id: string) { return id; }");

  it("flags a verified handler that never reads event.id", () => {
    const r = run({ [WEBHOOK]: handler('  if (event.type === "invoice.paid") await fulfil();') + "async function fulfil() {}\n" });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-no-idempotency:5"]);
    expect(r.findings.find((f) => f.rule === "stripe-webhook-no-idempotency")!.severity).toBe("medium");
  });

  it("accepts event.id, a destructured id, or a helper with an idempotency-style name", () => {
    expect(stripeFindings(run({ [WEBHOOK]: handler("  await record(event.id);") }))).toEqual([]);
    expect(stripeFindings(run({ [WEBHOOK]: handler("  const { id } = event;\n  await record(id);") }))).toEqual([]);
    expect(stripeFindings(run({ [WEBHOOK]: handler("  await ensureIdempotent(event);") + "declare function ensureIdempotent(e: unknown): Promise<void>;\n" }))).toEqual([]);
  });

  it("accepts custom helper names from the config", () => {
    const text = handler("  await claimEvent(event);") + "declare function claimEvent(e: unknown): Promise<void>;\n";
    expect(stripeFindings(run({ [WEBHOOK]: text }))).toEqual(["stripe-webhook-no-idempotency:5"]);
    expect(stripeFindings(run({ [WEBHOOK]: text }, { config: { idempotencyHelpers: ["claimEvent"] } }))).toEqual([]);
  });
});

describe("stripe-webhook-unknown-event-error", () => {
  const withDefault = (body: string) =>
    lines(HEAD, "export async function POST(request: Request) {", "  const event = stripe.webhooks.constructEvent(await request.text(), 's', 'w');", "  await record(event.id);", "  switch (event.type) {", '    case "invoice.paid":', "      break;", "    default:", body, "  }", "  return new Response(null);", "}", "async function record(id: string) { return id; }");

  it("flags a default branch that returns an error status", () => {
    const r = run({ [WEBHOOK]: withDefault('      return NextResponse.json({ error: "unhandled" }, { status: 500 });') + 'import { NextResponse } from "next/server";\n' });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-unknown-event-error:10"]);
    expect(r.findings.find((f) => f.rule === "stripe-webhook-unknown-event-error")!.title).toContain("returns 500");
  });

  it("flags a default branch that throws, and a 400", () => {
    expect(stripeFindings(run({ [WEBHOOK]: withDefault("      throw new Error('unhandled event');") }))).toEqual(["stripe-webhook-unknown-event-error:10"]);
    expect(stripeFindings(run({ [WEBHOOK]: withDefault("      return new Response('no', { status: 400 });") }))).toEqual(["stripe-webhook-unknown-event-error:10"]);
  });

  it("is quiet when unknown events are acknowledged", () => {
    expect(stripeFindings(run({ [WEBHOOK]: withDefault("      console.log('ignored', event.type);\n      break;") }))).toEqual([]);
  });

  it("flags the final else of an if chain on event.type", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const event = stripe.webhooks.constructEvent(await request.text(), 's', 'w');", "  await record(event.id);", '  if (event.type === "invoice.paid") {', "    await record('a');", '  } else if (event.type === "invoice.voided") {', "    await record('b');", "  } else {", "    return new Response('unknown', { status: 500 });", "  }", "  return new Response(null);", "}", "async function record(id: string) { return id; }"),
    });
    expect(stripeFindings(r)).toEqual(["stripe-webhook-unknown-event-error:11"]);
  });

  it("does not mistake a failure in the processing path for the unknown-event path", () => {
    const r = run({
      [WEBHOOK]: lines(HEAD, "export async function POST(request: Request) {", "  const event = stripe.webhooks.constructEvent(await request.text(), 's', 'w');", "  await record(event.id);", "  try {", "    await record('x');", "  } catch {", "    return new Response('retry', { status: 500 });", "  }", "  return new Response(null);", "}", "async function record(id: string) { return id; }"),
    });
    expect(stripeFindings(r)).toEqual([]);
  });
});

describe("stripe-checkout-client-price", () => {
  const route = (body: string) => lines(HEAD, "const PRICES: Record<string, string> = { pro: 'price_pro_id' };", "export async function POST(request: Request) {", "  const body = await request.json();", body, "  return Response.json({ url: session.url });", "}");

  it("flags an amount taken from the request as high", () => {
    const r = run({ "app/api/checkout/route.ts": route("  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price_data: { currency: 'usd', unit_amount: body.amount, product_data: { name: 'x' } }, quantity: 1 }] });") });
    const f = r.findings.filter((x) => x.rule === "stripe-checkout-client-price");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", line: 6 });
  });

  it("follows the value through variables and Number()", () => {
    const r = run({ "app/api/checkout/route.ts": route("  const cents = Number(body.total) * 100;\n  const session = await stripe.paymentIntents.create({ amount: cents, currency: 'usd' });") });
    expect(stripeFindings(r)).toEqual(["stripe-checkout-client-price:7"]);
  });

  it("flags a price id from the request as medium and a whole cart from the request as high", () => {
    const price = run({ "app/api/checkout/route.ts": route("  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: body.priceId, quantity: 1 }] });") });
    const cart = run({ "app/api/checkout/route.ts": route("  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: body.items });") });
    expect(price.findings.find((f) => f.rule === "stripe-checkout-client-price")).toMatchObject({ severity: "medium" });
    expect(cart.findings.find((f) => f.rule === "stripe-checkout-client-price")).toMatchObject({ severity: "high" });
  });

  it("accepts a server-side lookup keyed by client input", () => {
    const r = run({ "app/api/checkout/route.ts": route("  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: PRICES[body.plan], quantity: 1 }] });") });
    expect(stripeFindings(r)).toEqual([]);
  });

  it("accepts mapped line items whose price comes from the server table", () => {
    const r = run({ "app/api/checkout/route.ts": route("  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: body.items.map((i: { plan: string; qty: number }) => ({ price: PRICES[i.plan], quantity: i.qty })) });") });
    expect(stripeFindings(r)).toEqual([]);
  });

  it("applies to server actions through their parameters", () => {
    const r = run({ "app/actions.ts": lines('"use server";', HEAD, "export async function buy(amount: number) {", "  const s = await stripe.paymentIntents.create({ amount, currency: 'usd' });", "  return s.client_secret;", "}") });
    expect(stripeFindings(r)).toEqual(["stripe-checkout-client-price:5"]);
  });
});

describe("stripe-customer-unchecked", () => {
  const route = (body: string) => lines(HEAD, "export async function POST(request: Request) {", "  const body = await request.json();", body, "  return Response.json({});", "}");

  it("flags a customer id from the request in a billing portal session", () => {
    const r = run({ "app/api/portal/route.ts": route("  const s = await stripe.billingPortal.sessions.create({ customer: body.customerId, return_url: 'https://app.example.test' });") });
    expect(stripeFindings(r)).toEqual(["stripe-customer-unchecked:5"]);
    expect(r.findings.find((f) => f.rule === "stripe-customer-unchecked")!.severity).toBe("high");
  });

  it("flags a subscription id from the request passed straight to cancel", () => {
    const r = run({ "app/api/cancel/route.ts": route("  await stripe.subscriptions.cancel(body.subscriptionId);") });
    expect(stripeFindings(r)).toEqual(["stripe-customer-unchecked:5"]);
  });

  it("is quiet when the id is resolved on the server", () => {
    const r = run({ "app/api/portal/route.ts": route("  const customerId = await lookupCustomerFor(body.userHint);\n  const s = await stripe.billingPortal.sessions.create({ customer: customerId });") + "declare function lookupCustomerFor(x: string): Promise<string>;\n" });
    expect(stripeFindings(r)).toEqual([]);
  });

  it("does not flag creating a customer from request data", () => {
    const r = run({ "app/api/customer/route.ts": route("  await stripe.customers.create({ email: body.email });") });
    expect(stripeFindings(r)).toEqual([]);
  });
});
