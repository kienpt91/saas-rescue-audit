import { describe, expect, it } from "vitest";
import { keys, of, run } from "./helpers.js";

const lines = (...l: string[]): string => l.join("\n") + "\n";
const ROUTE = "app/api/projects/route.ts";

describe("api-route-no-auth", () => {
  it("flags a route handler that writes without any auth call, as critical, at the handler", () => {
    const r = run({ [ROUTE]: lines("export async function POST(request: Request) {", "  const body = await request.json();", '  const { data } = await supabase.from("projects").insert({ name: body.name });', "  return Response.json(data);", "}") });
    expect(keys(r)).toEqual([`api-route-no-auth@${ROUTE}:1`]);
    const f = r.findings[0]!;
    expect(f.severity).toBe("critical");
    expect(f.title).toBe("POST handler writes data without an auth check");
    expect(f.evidence).toBe('L1: export async function POST(request: Request) {\nL3: const { data } = await supabase.from("projects").insert({ name: body.name });');
  });

  it("rates a read-only handler high", () => {
    const r = run({ [ROUTE]: lines("export async function GET() {", '  const { data } = await supabase.from("projects").select("*");', "  return Response.json(data);", "}") });
    expect(of(r, "api-route-no-auth")[0]!.severity).toBe("high");
  });

  it.each([
    ["supabase.auth.getUser", "const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response(null, { status: 401 });"],
    ["auth()", "const { userId } = await auth();\n  if (!userId) return new Response(null, { status: 401 });"],
    ["getServerSession", "const session = await getServerSession(authOptions);\n  if (!session) return new Response(null, { status: 401 });"],
    ["requireUser", "const user = await requireUser();"],
  ])("accepts %s as an auth check", (_name, check) => {
    const r = run({ [ROUTE]: lines("export async function GET() {", `  ${check}`, '  const { data } = await supabase.from("projects").select("*");', "  return Response.json(data);", "}") });
    expect(of(r, "api-route-no-auth")).toEqual([]);
  });

  it("accepts a higher-order wrapper", () => {
    const r = run({ [ROUTE]: lines("export const POST = withAuth(async (request: Request, user: { id: string }) => {", '  await supabase.from("projects").insert({ name: "x", user_id: user.id });', "  return new Response(null);", "});") });
    expect(of(r, "api-route-no-auth")).toEqual([]);
  });

  it("recognises a helper declared in the same file that performs the check", () => {
    const text = lines(
      "async function currentMember() {",
      "  const { data } = await supabase.auth.getUser();",
      "  if (!data.user) throw new Response(null, { status: 401 });",
      "  return data.user;",
      "}",
      "export async function GET() {",
      "  const member = await currentMember();",
      '  const { data } = await supabase.from("projects").select("*").eq("user_id", member.id);',
      "  return Response.json(data);",
      "}",
    );
    expect(of(run({ [ROUTE]: text }), "api-route-no-auth")).toEqual([]);
  });

  it("takes extra helper names from the config", () => {
    const text = lines("export async function GET() {", "  await assertOrgMember();", '  const { data } = await supabase.from("projects").select("*");', "  return Response.json(data);", "}");
    expect(of(run({ [ROUTE]: text }), "api-route-no-auth")).toHaveLength(1);
    expect(of(run({ [ROUTE]: text }, { config: { authHelpers: ["assertOrgMember"] } }), "api-route-no-auth")).toEqual([]);
  });

  it("does not flag a handler that touches no data, or a route listed in publicRoutes", () => {
    const health = run({ "app/api/health/route.ts": lines("export async function GET() {", "  return Response.json({ ok: true });", "}") });
    expect(health.findings).toEqual([]);
    const text = lines("export async function GET() {", '  const { data } = await supabase.from("plans").select("*");', "  return Response.json(data);", "}");
    const open = run({ "app/api/plans/route.ts": text }, { config: { publicRoutes: ["app/api/plans/**"] } });
    expect(of(open, "api-route-no-auth")).toEqual([]);
  });

  it("treats reading the Authorization header as a credential check (cron-style routes)", () => {
    const text = lines("export async function GET(request: Request) {", '  if (request.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });', '  await supabase.from("jobs").delete().lt("created_at", "2020-01-01");', "  return new Response(null);", "}");
    expect(of(run({ "app/api/cron/route.ts": text }), "api-route-no-auth")).toEqual([]);
  });

  it("flags server actions, in a use server file and inline", () => {
    const file = run({ "app/actions.ts": lines('"use server";', "export async function removeArchived() {", '  await supabase.from("projects").delete().eq("archived", true);', "}") });
    expect(keys(file)).toEqual(["api-route-no-auth@app/actions.ts:2"]);
    expect(file.findings[0]!.title).toBe("Server action removeArchived writes data without an auth check");
    const inline = run({
      "app/page.tsx": lines("export default function Page() {", "  async function save(formData: FormData) {", '    "use server";', '    await supabase.from("notes").insert({ body: formData.get("body") });', "  }", "  return <form action={save} />;", "}"),
    });
    expect(keys(inline)).toEqual(["api-route-no-auth@app/page.tsx:2"]);
  });

  it("accepts an authenticated server action", () => {
    const r = run({ "app/actions.ts": lines('"use server";', "export async function save(body: string) {", "  const { data: { user } } = await supabase.auth.getUser();", '  await supabase.from("notes").insert({ body, user_id: user!.id });', "}") });
    expect(r.findings).toEqual([]);
  });

  it("recognises prisma and tagged-template sql access", () => {
    const prisma = run({ [ROUTE]: lines("export async function GET() {", "  return Response.json(await prisma.project.findMany());", "}") });
    const tagged = run({ [ROUTE]: lines("export async function POST() {", "  await sql`delete from projects`;", "  return new Response(null);", "}") });
    expect(of(prisma, "api-route-no-auth")[0]!.severity).toBe("high");
    expect(of(tagged, "api-route-no-auth")[0]!.severity).toBe("critical");
  });

  it("follows one level of same-file data helpers", () => {
    const text = lines('async function listProjects() { return supabase.from("projects").select("*"); }', "export async function GET() {", "  const { data } = await listProjects();", "  return Response.json(data);", "}");
    expect(keys(run({ [ROUTE]: text }))).toEqual([`api-route-no-auth@${ROUTE}:2`]);
  });

  it("reads the pages router default export", () => {
    const r = run({ "pages/api/notes.ts": lines("export default async function handler(req: NextApiRequest, res: NextApiResponse) {", '  const { data } = await supabase.from("notes").select("*");', "  res.status(200).json(data);", "}") });
    expect(keys(r)).toEqual(["api-route-no-auth@pages/api/notes.ts:1"]);
  });

  it("ignores client components and files that are not entry points", () => {
    const client = run({ "components/List.tsx": lines('"use client";', "export async function load() {", '  return supabase.from("notes").select("*");', "}") });
    const lib = run({ "lib/db.ts": lines("export async function load() {", '  return supabase.from("notes").select("*");', "}") });
    expect(client.findings).toEqual([]);
    expect(lib.findings).toEqual([]);
  });

  it("leaves Stripe webhook handlers to the Stripe rules", () => {
    const text = lines('import Stripe from "stripe";', "const stripe = new Stripe('x');", "export async function POST(request: Request) {", "  const event = stripe.webhooks.constructEvent(await request.text(), 's', 'w');", '  await supabase.from("orders").update({ paid: true }).eq("id", event.id);', "  return new Response(null);", "}");
    expect(of(run({ "app/api/stripe/webhook/route.ts": text }), "api-route-no-auth")).toEqual([]);
  });
});

const authed = (body: string, signature = "request: Request, { params }: { params: { id: string } }") =>
  lines(`export async function PATCH(${signature}) {`, "  const { data: { user } } = await supabase.auth.getUser();", "  if (!user) return new Response(null, { status: 401 });", "  const body = await request.json();", body, "  return new Response(null);", "}");

describe("api-idor", () => {
  it("flags an update filtered only by the id from route params", () => {
    const r = run({ "app/api/projects/[id]/route.ts": authed('  await supabase.from("projects").update(body).eq("id", params.id);') });
    expect(keys(r)).toEqual(["api-idor@app/api/projects/[id]/route.ts:5"]);
    expect(r.findings[0]).toMatchObject({ severity: "high" });
    expect(r.findings[0]!.title).toBe("Write on projects filtered only by id from the request");
  });

  it("is quiet when the query also filters by the signed-in user", () => {
    const r = run({ "app/api/projects/[id]/route.ts": authed('  await supabase.from("projects").update(body).eq("id", params.id).eq("user_id", user.id);') });
    expect(r.findings).toEqual([]);
  });

  it("covers prisma where objects, with and without an owner key", () => {
    const bad = run({ "app/api/p/[id]/route.ts": authed("  await prisma.project.update({ where: { id: params.id }, data: body });") });
    const good = run({ "app/api/p/[id]/route.ts": authed("  await prisma.project.update({ where: { id: params.id, userId: user.id }, data: body });") });
    expect(keys(bad)).toEqual(["api-idor@app/api/p/[id]/route.ts:5"]);
    expect(good.findings).toEqual([]);
  });

  it("covers drizzle where() with eq and and()", () => {
    const bad = run({ "app/api/p/[id]/route.ts": authed("  await db.delete(projects).where(eq(projects.id, params.id));") });
    const good = run({ "app/api/p/[id]/route.ts": authed("  await db.delete(projects).where(and(eq(projects.id, params.id), eq(projects.userId, user.id)));") });
    expect(keys(bad)).toEqual(["api-idor@app/api/p/[id]/route.ts:5"]);
    expect(good.findings).toEqual([]);
  });

  it("follows the id through await params and destructuring (Next 15 style)", () => {
    const r = run({
      "app/api/p/[id]/route.ts": lines("export async function DELETE(request: Request, ctx: { params: Promise<{ id: string }> }) {", "  const { data: { user } } = await supabase.auth.getUser();", "  if (!user) return new Response(null, { status: 401 });", "  const { id } = await ctx.params;", '  await supabase.from("projects").delete().eq("id", id);', "  return new Response(null);", "}"),
    });
    expect(keys(r)).toEqual(["api-idor@app/api/p/[id]/route.ts:5"]);
  });

  it("flags an owner column set from the request body", () => {
    const r = run({ "app/api/projects/route.ts": authed('  await supabase.from("projects").insert({ name: body.name, user_id: body.userId });', "request: Request") });
    expect(keys(r)).toEqual(["api-idor@app/api/projects/route.ts:5"]);
    expect(r.findings[0]!.title).toBe("Row owner user_id is set from the request");
  });

  it("flags filtering by an owner id supplied by the client", () => {
    const r = run({ "app/api/projects/route.ts": authed('  await supabase.from("projects").select("*").eq("user_id", body.userId);', "request: Request") });
    expect(keys(r)).toEqual(["api-idor@app/api/projects/route.ts:5"]);
    expect(r.findings[0]!.severity).toBe("medium");
  });

  it("does not flag ids that come from the session", () => {
    const r = run({ "app/api/me/route.ts": authed('  await supabase.from("profiles").update(body).eq("id", user.id);', "request: Request") });
    expect(r.findings).toEqual([]);
  });

  it("applies to server action parameters", () => {
    const r = run({
      "app/actions.ts": lines('"use server";', "export async function archive(id: string) {", "  const { data: { user } } = await supabase.auth.getUser();", '  await supabase.from("projects").update({ archived: true }).eq("id", id);', "}"),
    });
    expect(keys(r)).toEqual(["api-idor@app/actions.ts:4"]);
  });

  it("treats a lookup through a server-side map as untainted", () => {
    const r = run({ "app/api/p/route.ts": authed('  await supabase.from("projects").update(body).eq("id", ids[body.key]);', "request: Request") });
    expect(r.findings).toEqual([]);
  });

  it("honours tenantColumns for the ownership filter", () => {
    const text = authed('  await supabase.from("projects").update(body).eq("id", params.id).eq("workspace_ref", user.id);');
    const plain = run({ "app/api/p/[id]/route.ts": text });
    const configured = run({ "app/api/p/[id]/route.ts": text }, { config: { tenantColumns: ["workspace_ref"] } });
    expect(of(plain, "api-idor")).toHaveLength(1);
    expect(of(configured, "api-idor")).toEqual([]);
  });
});
