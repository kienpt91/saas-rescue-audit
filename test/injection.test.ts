import { describe, expect, it } from "vitest";
import { keys, of, run } from "./helpers.js";

const lines = (...l: string[]): string => l.join("\n") + "\n";
const tsx = (body: string, props = "{ html }: { html: string }") => lines(`export function Post(${props}) {`, "  return (", body, "  );", "}");

describe("unsafe-html", () => {
  it("flags dangerouslySetInnerHTML with a non-constant value, at the attribute", () => {
    const r = run({ "components/Post.tsx": tsx("    <div dangerouslySetInnerHTML={{ __html: html }} />") });
    expect(keys(r)).toEqual(["unsafe-html@components/Post.tsx:3"]);
    expect(r.findings[0]).toMatchObject({ severity: "high", title: "dangerouslySetInnerHTML receives non-constant input" });
  });

  it("accepts constants: literal, template without substitutions, and a const string in the same file", () => {
    const r = run({
      "components/Static.tsx": lines('const STYLE = "a{color:red}";', "export const A = () => <style dangerouslySetInnerHTML={{ __html: STYLE }} />;", "export const B = () => <style dangerouslySetInnerHTML={{ __html: `b{color:blue}` }} />;", 'export const C = () => <p dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;'),
    });
    expect(r.findings).toEqual([]);
  });

  it("flags template literals with substitutions and concatenation with a variable", () => {
    const r = run({ "components/T.tsx": lines("export const A = ({ n }: { n: string }) => <p dangerouslySetInnerHTML={{ __html: `<b>${n}</b>` }} />;", 'export const B = ({ n }: { n: string }) => <p dangerouslySetInnerHTML={{ __html: "<b>" + n + "</b>" }} />;') });
    expect(keys(r)).toEqual(["unsafe-html@components/T.tsx:1", "unsafe-html@components/T.tsx:2"]);
  });

  it("accepts a recognised sanitizer, including names from the config", () => {
    const text = lines("export const A = ({ h }: { h: string }) => <p dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />;", "export const B = ({ h }: { h: string }) => <p dangerouslySetInnerHTML={{ __html: renderSafeMarkdown(h) }} />;");
    expect(keys(run({ "components/S.tsx": text }))).toEqual(["unsafe-html@components/S.tsx:2"]);
    expect(run({ "components/S.tsx": text }, { config: { sanitizers: ["renderSafeMarkdown"] } }).findings).toEqual([]);
  });

  it("rates JSON.stringify (JSON-LD) low and explains the </script> problem", () => {
    const r = run({ "components/Ld.tsx": tsx('    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />', "{ data }: { data: object }") });
    expect(r.findings[0]).toMatchObject({ rule: "unsafe-html", severity: "low" });
    expect(r.findings[0]!.message).toContain("</script>");
  });

  it("flags a prop that is not an object literal, since it cannot be inspected", () => {
    const r = run({ "components/P.tsx": tsx("    <div dangerouslySetInnerHTML={props.inner} />", "props: { inner: { __html: string } }") });
    expect(keys(r)).toEqual(["unsafe-html@components/P.tsx:3"]);
  });

  it("flags innerHTML assignment, insertAdjacentHTML and document.write with variables, not with constants", () => {
    const bad = run({ "lib/dom.ts": lines("export function a(el: HTMLElement, v: string) {", "  el.innerHTML = v;", "  el.insertAdjacentHTML('beforeend', v);", "  document.write(v);", "}") });
    const good = run({ "lib/dom.ts": lines("export function a(el: HTMLElement) {", "  el.innerHTML = '<b>x</b>';", "  el.insertAdjacentHTML('beforeend', '<i>y</i>');", "}") });
    expect(keys(bad)).toEqual(["unsafe-html@lib/dom.ts:2", "unsafe-html@lib/dom.ts:3", "unsafe-html@lib/dom.ts:4"]);
    expect(good.findings).toEqual([]);
  });
});

describe("open-redirect", () => {
  const callback = (body: string) => lines("export async function GET(request: Request) {", "  const { searchParams, origin } = new URL(request.url);", '  const next = searchParams.get("next") ?? "/";', body, "}");

  it("flags the common auth-callback pattern of prefixing the origin to a query parameter", () => {
    const r = run({ "app/auth/callback/route.ts": callback("  return NextResponse.redirect(`${origin}${next}`);") });
    expect(keys(r).filter((k) => k.startsWith("open-redirect"))).toEqual(["open-redirect@app/auth/callback/route.ts:4"]);
    expect(r.findings.find((f) => f.rule === "open-redirect")!.severity).toBe("medium");
  });

  it("accepts a startsWith guard on the value or on a value derived from it", () => {
    const direct = callback('  if (!next.startsWith("/") || next.startsWith("//")) return NextResponse.redirect(`${origin}/`);\n  return NextResponse.redirect(`${origin}${next}`);');
    const derived = callback('  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/";\n  return NextResponse.redirect(`${origin}${safe}`);');
    expect(of(run({ "app/auth/callback/route.ts": direct }), "open-redirect")).toEqual([]);
    expect(of(run({ "app/auth/callback/route.ts": derived }), "open-redirect")).toEqual([]);
  });

  it("accepts an allow-list check, an equality check and a safe-redirect helper", () => {
    const allow = callback("  if (!ALLOWED.includes(next)) return new Response(null, { status: 400 });\n  return NextResponse.redirect(`${origin}${next}`);");
    const eq = callback('  if (next === "/dashboard") return NextResponse.redirect(`${origin}${next}`);\n  return new Response(null);');
    const helper = callback("  return NextResponse.redirect(`${origin}${safeRedirectPath(next)}`);");
    for (const text of [allow, eq, helper]) expect(of(run({ "app/auth/callback/route.ts": text }), "open-redirect")).toEqual([]);
  });

  it("does not take an unrelated check on the same query object as a guard", () => {
    const text = callback('  if (searchParams.get("type") === "recovery") return new Response(null);\n  return NextResponse.redirect(`${origin}${next}`);');
    expect(of(run({ "app/auth/callback/route.ts": text }), "open-redirect")).toHaveLength(1);
  });

  it("accepts targets whose host is fixed: a path prefix, a literal host or new URL(path, request.url)", () => {
    const prefix = lines("export async function GET(request: Request) {", "  const { searchParams } = new URL(request.url);", "  return redirect('/login?next=' + searchParams.get('next'));", "}");
    const url = lines("export async function GET(request: Request) {", "  return NextResponse.redirect(new URL('/dashboard', request.url));", "}");
    const base = lines("export async function GET(request: Request) {", "  const { searchParams } = new URL(request.url);", "  return NextResponse.redirect(`${process.env.SITE_URL}/${searchParams.get('p')}`);", "}");
    for (const text of [prefix, url, base]) expect(of(run({ "app/r/route.ts": text }), "open-redirect")).toEqual([]);
  });

  it("flags new URL(next, request.url), which can still point anywhere", () => {
    const text = callback("  return NextResponse.redirect(new URL(next, request.url));");
    expect(of(run({ "app/r/route.ts": text }), "open-redirect")).toHaveLength(1);
  });

  it("flags server actions and the pages router", () => {
    const action = run({ "app/actions.ts": lines('"use server";', "export async function login(formData: FormData) {", '  redirect(formData.get("returnTo") as string);', "}") });
    const pages = run({ "pages/api/go.ts": lines("export default function handler(req: NextApiRequest, res: NextApiResponse) {", "  res.redirect(req.query.url as string);", "}") });
    expect(keys(action)).toEqual(["open-redirect@app/actions.ts:3"]);
    expect(keys(pages)).toEqual(["open-redirect@pages/api/go.ts:2"]);
  });

  it("flags client-side navigation from useSearchParams and location.search, not constants", () => {
    const hook = run({ "components/Login.tsx": lines('"use client";', "export function Login() {", "  const params = useSearchParams();", "  const router = useRouter();", '  const go = () => router.push(params.get("next") as string);', '  const home = () => router.push("/home");', "  return null;", "}") });
    const loc = run({ "components/Go.tsx": lines('"use client";', "export function go() {", '  window.location.href = new URLSearchParams(window.location.search).get("r") as string;', "}") });
    expect(keys(hook)).toEqual(["open-redirect@components/Login.tsx:5"]);
    expect(keys(loc)).toEqual(["open-redirect@components/Go.tsx:3"]);
  });

  it("does not flag constant redirects", () => {
    const r = run({ "app/auth/logout/route.ts": lines("export async function POST() {", '  return NextResponse.redirect(new URL("/login", "https://app.example.test"));', "}") });
    expect(of(r, "open-redirect")).toEqual([]);
  });
});
