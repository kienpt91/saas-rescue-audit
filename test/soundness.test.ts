import { describe, expect, it } from "vitest";
import { buildSqlModel, foldConstant, scopesToCaller } from "../src/sql/model.js";
import { tokenize } from "../src/sql/tokenizer.js";
import type { AuditResult } from "../src/types.js";
import { keys, of, run } from "./helpers.js";

const M = "supabase/migrations/001.sql";
const T = "create table public.t (id int primary key, user_id uuid);\nalter table public.t enable row level security;\n";
const fold = (expr: string) => foldConstant(tokenize(expr));
const lines = (...l: string[]): string => l.join("\n") + "\n";

describe("policy expressions that are always true", () => {
  it.each([
    "true or false",
    "false or true",
    "true and true",
    "not false",
    "not (not true)",
    "true = true",
    "1 = 1.0",
    "'x' = 'x'",
    "true::boolean",
    "(1 = 1) or auth.uid() = user_id",
    "auth.uid() is null or true",
    "((true))",
    "2 <> 3",
    "false = false",
  ])("folds %s to true", (expr) => {
    expect(fold(expr)).toBe("true");
  });

  it.each(["true and false", "not true", "1 = 2", "'a' = 'b'", "false or false", "false and auth.uid() = user_id"])("folds %s to false", (expr) => {
    expect(fold(expr)).toBe("false");
  });

  it.each(["auth.uid() = user_id", "user_id is not null", "true and auth.uid() = user_id", "false or user_id = auth.uid()", "role() = 'x'", "x = x", "1 = '1'"])("leaves %s undecided", (expr) => {
    expect(fold(expr)).toBe("unknown");
  });

  it("flags every always-true spelling as an open policy and never flags a real condition", () => {
    for (const expr of ["true or false", "true and true", "not false", "true = true", "1 = 1.0", "'x' = 'x'", "true::boolean", "auth.uid() is null or true"]) {
      const r = run({ [M]: `${T}create policy p on public.t for select to authenticated using (${expr});` });
      expect(of(r, "supabase-policy-permissive"), expr).toHaveLength(1);
    }
    for (const expr of ["auth.uid() = user_id", "true and auth.uid() = user_id", "false or user_id = auth.uid()", "1 = 2"]) {
      const r = run({ [M]: `${T}create policy p on public.t for select to authenticated using (${expr});` });
      expect(of(r, "supabase-policy-permissive"), expr).toEqual([]);
    }
  });

  it("reports a policy that is too deeply grouped to fold, never as safe", () => {
    expect(fold("not ".repeat(100) + "true")).toBe("too-deep");
  });
});

describe("owner columns must be tied to the caller", () => {
  const scoped = (expr: string, col = "user_id") => scopesToCaller(tokenize(expr), col);

  it("accepts auth.uid(), auth.jwt() and current_setting comparisons and membership helpers", () => {
    expect(scoped("auth.uid() = user_id")).toBe(true);
    expect(scoped("(select auth.uid()) = user_id")).toBe(true);
    expect(scoped("user_id = (auth.jwt() ->> 'sub')::uuid")).toBe(true);
    expect(scoped("user_id::text = current_setting('app.user')")).toBe(true);
    expect(scoped("is_member(org_id)", "org_id")).toBe(true);
    expect(scoped("exists (select 1 from members m where m.user_id = auth.uid() and m.org_id = org_id)", "org_id")).toBe(true);
  });

  it("rejects mentions that do not scope anything", () => {
    expect(scoped("user_id is not null")).toBe(false);
    expect(scoped("user_id = user_id")).toBe(false);
    expect(scoped("user_id in (1, 2)")).toBe(false);
    expect(scoped("true or user_id = auth.uid()")).toBe(false);
    expect(scoped("auth.uid() is not null")).toBe(false);
  });

  it("reports a table whose only policy merely mentions the owner column", () => {
    const r = run({ [M]: `${T}create policy p on public.t for select to authenticated using (user_id is not null);` });
    expect(of(r, "supabase-tenant-unscoped")).toHaveLength(1);
    const ok = run({ [M]: `${T}create policy p on public.t for select to authenticated using (user_id = auth.uid());` });
    expect(of(ok, "supabase-tenant-unscoped")).toEqual([]);
  });

  it("reports both problems when a policy is open and only pretends to be scoped", () => {
    const r = run({ [M]: `${T}create policy p on public.t for select to authenticated using (true or user_id = auth.uid());` });
    expect(keys(r).sort()).toEqual([`supabase-policy-permissive@${M}:3`, `supabase-tenant-unscoped@${M}:1`]);
  });
});

describe("identifier case in migrations", () => {
  it("keeps a quoted mixed-case table apart from the lower-case one", () => {
    const r = run({ [M]: lines('create table "Orders" (id int, user_id uuid);', "create table orders (id int);", "alter table orders enable row level security;", "create policy p on orders for select to authenticated using (auth.uid() is not null);") });
    expect(keys(r)).toEqual([`supabase-rls-missing@${M}:1`]);
    expect(r.findings[0]!.title).toBe("Table public.Orders has no row level security");
  });

  it("does not let DROP TABLE of one spelling remove the other", () => {
    const r = run({ [M]: lines('create table "Orders" (id int);', "create table orders (id int);", "alter table orders enable row level security;", 'drop table "Orders";') });
    expect(r.findings.map((f) => f.rule)).toEqual(["supabase-policy-missing"]);
  });

  it("treats unquoted names as case-insensitive, as PostgreSQL does", () => {
    const r = run({ [M]: lines("create table Orders (id int);", "alter table ORDERS enable row level security;", 'create policy p on "orders" for select to authenticated using (auth.uid() is not null);') });
    expect(r.findings).toEqual([]);
  });

  it("does not reset row level security when CREATE TABLE IF NOT EXISTS runs again", () => {
    const r = run({ [M]: lines("create table public.t (id int);", "alter table public.t enable row level security;", "create policy p on public.t for select to authenticated using (auth.uid() is not null);"), "supabase/migrations/002.sql": "create table if not exists public.t (id int);\n" });
    expect(r.findings).toEqual([]);
  });
});

describe("SQL that this tool cannot read", () => {
  it("warns when a DO block or function body mentions policies or RLS, and does not count them", () => {
    const sql = lines("create table public.t (id int);", "alter table public.t enable row level security;", "create policy ok on public.t for select to authenticated using (auth.uid() is not null);", "do $$ begin", "  execute 'create policy open on public.t for all using (true)';", "end $$;");
    const r = run({ [M]: sql });
    expect(r.warnings).toEqual([`${M}:4: a function or DO block mentions policies, row level security or EXECUTE; SQL inside dollar-quoted bodies is not analysed`]);
    expect(of(r, "supabase-policy-permissive")).toEqual([]);
  });

  it("is quiet about ordinary functions", () => {
    const r = run({ [M]: "create function f() returns int language sql as $$ select 1 $$;\n" });
    expect(r.warnings).toEqual([]);
  });

  it("builds the model with isolated failures per file", () => {
    const seen: string[] = [];
    const model = buildSqlModel(
      [
        { path: "a.sql", text: "create table public.a (id int);" },
        { path: "b.sql", text: "create table public.b (id int);" },
      ],
      { guard: (path, fn) => (seen.push(path), fn()) },
    );
    expect(seen).toEqual(["a.sql", "b.sql"]);
    expect([...model.tables.keys()]).toEqual(["public.a", "public.b"]);
  });
});

const HEAD = 'import Stripe from "stripe";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);';
const WEBHOOK = "app/api/stripe/webhook/route.ts";
const stripeRules = (r: AuditResult): string[] => r.findings.filter((f) => f.rule.startsWith("stripe-")).map((f) => f.rule);

describe("webhook verification must really happen", () => {
  const tail = ["  await record(event.id);", "  return new Response(null);", "}", "async function record(id: string) { return id; }"];

  it("does not accept a function that merely has the name constructEvent", () => {
    const text = lines(HEAD, "function constructEvent(body: string) { return JSON.parse(body); }", "export async function POST(request: Request) {", "  const event = constructEvent(await request.text());", ...tail);
    expect(stripeRules(run({ [WEBHOOK]: text }))).toContain("stripe-webhook-unverified");
  });

  it("does not accept verification in a function that is never called", () => {
    const text = lines(HEAD, "function unused(raw: string) { return stripe.webhooks.constructEvent(raw, 's', 'w'); }", "export async function POST(request: Request) {", "  const event = JSON.parse(await request.text());", ...tail);
    expect(stripeRules(run({ [WEBHOOK]: text }))).toContain("stripe-webhook-unverified");
  });

  it("does not accept verification inside if (false)", () => {
    const text = lines(HEAD, "export async function POST(request: Request) {", "  let event: Stripe.Event;", "  if (false) {", "    event = stripe.webhooks.constructEvent(await request.text(), 's', 'w');", "  } else {", "    event = JSON.parse(await request.text());", "  }", ...tail);
    expect(stripeRules(run({ [WEBHOOK]: text }))).toContain("stripe-webhook-unverified");
  });

  it("accepts verification in a same-file helper that the handler calls", () => {
    const text = lines(HEAD, "function verify(raw: string, sig: string) { return stripe.webhooks.constructEvent(raw, sig, 'w'); }", "export async function POST(request: Request) {", "  const event = verify(await request.text(), 's');", ...tail);
    expect(stripeRules(run({ [WEBHOOK]: text }))).toEqual([]);
  });

  it("accepts constructEventAsync on any receiver chain that includes webhooks", () => {
    const text = lines(HEAD, "export async function POST(request: Request) {", "  const event = await getStripe().webhooks.constructEventAsync(await request.text(), 's', 'w');", ...tail, "declare function getStripe(): Stripe;");
    expect(stripeRules(run({ [WEBHOOK]: text }))).toEqual([]);
  });

  it("accepts a verification helper named in authHelpers", () => {
    const text = lines(HEAD, "export async function POST(request: Request) {", "  const event = await verifyStripeRequest(request);", ...tail, "declare function verifyStripeRequest(r: Request): Promise<Stripe.Event>;");
    expect(stripeRules(run({ [WEBHOOK]: text }))).toEqual(["stripe-webhook-unverified"]);
    const configured = run({ [WEBHOOK]: text }, { config: { authHelpers: ["verifyStripeRequest"] } });
    expect(stripeRules(configured)).toEqual([]);
  });

  it("recognises a webhook by its event.type handling even in an oddly named route", () => {
    const text = lines(HEAD, "export async function POST(request: Request) {", "  const event = JSON.parse(await request.text());", "  const kind = event.type;", "  return new Response(kind);", "}");
    expect(stripeRules(run({ "app/api/payments/in/route.ts": text }))).toEqual(["stripe-webhook-unverified"]);
  });

  it("does not exempt a non-Stripe route from the auth rule because it calls something named constructEvent", () => {
    const text = lines("function constructEvent(x: string) { return x; }", "export async function POST(request: Request) {", "  constructEvent(await request.text());", '  await supabase.from("a").delete().eq("done", true);', "  return new Response(null);", "}");
    expect(of(run({ "app/api/other/route.ts": text }), "api-route-no-auth")).toHaveLength(1);
  });
});

describe("a redirect guard has to guard", () => {
  const callback = (body: string) => lines("export async function GET(request: Request) {", "  const { searchParams, origin } = new URL(request.url);", '  const next = searchParams.get("next") ?? "/";', body, "}");
  const flagged = (text: string) => of(run({ "app/auth/callback/route.ts": text }), "open-redirect");

  it("ignores a check whose result is thrown away", () => {
    expect(flagged(callback('  next.startsWith("/");\n  return NextResponse.redirect(`${origin}${next}`);'))).toHaveLength(1);
    expect(flagged(callback("  isSafeRedirect(next);\n  return NextResponse.redirect(`${origin}${next}`);"))).toHaveLength(1);
    expect(flagged(callback('  next === "/home";\n  return NextResponse.redirect(`${origin}${next}`);'))).toHaveLength(1);
  });

  it("ignores a check that happens after the redirect", () => {
    expect(flagged(callback('  const response = NextResponse.redirect(`${origin}${next}`);\n  if (!next.startsWith("/")) throw new Error("bad");\n  return response;'))).toHaveLength(1);
  });

  it("accepts a check used in an if, a ternary, or a boolean stored and used later", () => {
    expect(flagged(callback('  if (!next.startsWith("/")) return new Response(null, { status: 400 });\n  return NextResponse.redirect(`${origin}${next}`);'))).toEqual([]);
    expect(flagged(callback('  const to = next.startsWith("/") ? next : "/";\n  return NextResponse.redirect(`${origin}${to}`);'))).toEqual([]);
    expect(flagged(callback('  const ok = next.startsWith("/") && !next.startsWith("//");\n  if (!ok) return new Response(null, { status: 400 });\n  return NextResponse.redirect(`${origin}${next}`);'))).toEqual([]);
    expect(flagged(callback("  if (!isSafeRedirect(next)) return new Response(null, { status: 400 });\n  return NextResponse.redirect(`${origin}${next}`);"))).toEqual([]);
  });

  it("does not take a boolean that is stored and never used as a guard", () => {
    expect(flagged(callback('  const ok = next.startsWith("/");\n  return NextResponse.redirect(`${origin}${next}`);'))).toHaveLength(1);
  });
});
