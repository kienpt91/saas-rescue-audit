import { describe, expect, it } from "vitest";
import { keys, of, run } from "./helpers.js";

const lines = (...l: string[]): string => l.join("\n") + "\n";
const LOCK = { "package-lock.json": "{}" };
const PKG = JSON.stringify({ name: "x", dependencies: { next: "15.0.0" } }, null, 2) + "\n";

describe("cors-wildcard-credentials", () => {
  it("flags * together with credentials in a headers object", () => {
    const r = run({
      "app/api/a/route.ts": lines("export async function GET() {", "  return new Response('x', {", "    headers: {", '      "Access-Control-Allow-Origin": "*",', '      "Access-Control-Allow-Credentials": "true",', "    },", "  });", "}"),
    });
    expect(keys(r)).toEqual(["cors-wildcard-credentials@app/api/a/route.ts:4"]);
    expect(r.findings[0]).toMatchObject({ severity: "high", title: "CORS allows every origin together with credentials" });
  });

  it("flags a reflected Origin with credentials, via set() calls", () => {
    const r = run({
      "app/api/a/route.ts": lines("export async function GET(request: Request) {", "  const res = new Response('x');", '  res.headers.set("Access-Control-Allow-Origin", request.headers.get("origin") ?? "");', '  res.headers.set("Access-Control-Allow-Credentials", "true");', "  return res;", "}"),
    });
    expect(keys(r)).toEqual(["cors-wildcard-credentials@app/api/a/route.ts:3"]);
    expect(r.findings[0]!.title).toContain("reflects the request origin");
  });

  it("flags the same pair declared in next.config headers()", () => {
    const r = run({
      "next.config.mjs": lines("export default {", "  async headers() {", "    return [{ source: '/api/:path*', headers: [", "      { key: 'Access-Control-Allow-Origin', value: '*' },", "      { key: 'Access-Control-Allow-Credentials', value: 'true' },", "    ] }];", "  },", "};"),
    });
    expect(keys(r).filter((k) => k.startsWith("cors"))).toEqual(["cors-wildcard-credentials@next.config.mjs:4"]);
  });

  it("flags the cors package with origin: true and credentials: true", () => {
    const r = run({ "lib/cors.ts": lines('import cors from "cors";', "export const mw = cors({ origin: true, credentials: true });") });
    expect(keys(r)).toEqual(["cors-wildcard-credentials@lib/cors.ts:2"]);
  });

  it("does not flag a wildcard without credentials, an explicit origin, or a pair in different handlers", () => {
    const wildcard = run({ "app/api/a/route.ts": lines("export async function GET() {", "  return new Response('x', { headers: { 'Access-Control-Allow-Origin': '*' } });", "}") });
    const explicit = run({ "app/api/a/route.ts": lines("export async function GET() {", "  return new Response('x', { headers: { 'Access-Control-Allow-Origin': 'https://app.example.test', 'Access-Control-Allow-Credentials': 'true' } });", "}") });
    const split = run({ "app/api/a/route.ts": lines("export async function GET() {", "  return new Response('x', { headers: { 'Access-Control-Allow-Origin': '*' } });", "}", "export async function POST() {", "  return new Response('x', { headers: { 'Access-Control-Allow-Credentials': 'true' } });", "}") });
    for (const r of [wildcard, explicit, split]) expect(of(r, "cors-wildcard-credentials")).toEqual([]);
  });
});

describe("build-checks-disabled", () => {
  it("flags ignoreBuildErrors and ignoreDuringBuilds at their lines", () => {
    const r = run({ "next.config.js": lines("module.exports = {", "  typescript: { ignoreBuildErrors: true },", "  eslint: { ignoreDuringBuilds: true },", "};") });
    expect(keys(r).filter((k) => k.startsWith("build"))).toEqual(["build-checks-disabled@next.config.js:2", "build-checks-disabled@next.config.js:3"]);
  });

  it("is quiet when they are false or absent", () => {
    const r = run({ "next.config.js": lines("module.exports = {", "  typescript: { ignoreBuildErrors: false },", "};") });
    expect(of(r, "build-checks-disabled")).toEqual([]);
  });
});

describe("security-headers", () => {
  it("reports at info level when a Next.js project sets no security headers", () => {
    const r = run({ "next.config.mjs": "export default {};\n" });
    expect(r.findings.filter((f) => f.rule === "security-headers")).toMatchObject([{ severity: "info", file: "next.config.mjs", line: 1 }]);
  });

  it("falls back to package.json when there is no next.config", () => {
    const r = run({ "package.json": PKG, ...LOCK });
    expect(r.findings.filter((f) => f.rule === "security-headers")).toMatchObject([{ file: "package.json", line: 4 }]);
  });

  it("is quiet when headers are set in next.config or in middleware", () => {
    const cfg = run({ "next.config.mjs": lines("export default {", "  async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }]; },", "};") });
    const mw = run({ "next.config.mjs": "export default {};\n", "middleware.ts": "export function middleware() { const r = new Response(); r.headers.set('Content-Security-Policy', \"default-src 'self'\"); return r; }\n" });
    expect(of(cfg, "security-headers")).toEqual([]);
    expect(of(mw, "security-headers")).toEqual([]);
  });

  it("does nothing for a project that is not Next.js", () => {
    expect(run({ "src/index.ts": "export const x = 1;\n" }).findings).toEqual([]);
  });

  it("flags weakened values as low", () => {
    const r = run({
      "next.config.mjs": lines("export default {", "  async headers() {", "    return [{ source: '/(.*)', headers: [", "      { key: 'X-Frame-Options', value: 'ALLOWALL' },", "      { key: 'Content-Security-Policy', value: \"script-src 'self' 'unsafe-eval'\" },", "    ] }];", "  },", "};"),
    });
    expect(r.findings.filter((f) => f.rule === "security-headers").map((f) => [f.severity, f.line])).toEqual([
      ["low", 4],
      ["low", 5],
    ]);
  });
});

describe("no-rate-limit", () => {
  const login = lines("export async function POST(request: Request) {", "  const { email } = await request.json();", "  await sendMagicLink(email);", "  return new Response(null);", "}", "declare function sendMagicLink(e: string): Promise<void>;");

  it("reports auth routes at info level", () => {
    const r = run({ "app/api/auth/login/route.ts": login });
    expect(r.findings).toMatchObject([{ rule: "no-rate-limit", severity: "info", line: 1 }]);
  });

  it("reports webhook routes too, and ignores other routes", () => {
    const r = run({ "app/api/stripe/webhook/route.ts": login, "app/api/projects/route.ts": login });
    expect(keys(r)).toEqual(["no-rate-limit@app/api/stripe/webhook/route.ts:1"]);
  });

  it("is quiet when the file or the middleware mentions a limiter, or the config names one", () => {
    const inFile = run({ "app/api/auth/login/route.ts": 'import { Ratelimit } from "@upstash/ratelimit";\n' + login });
    const inMiddleware = run({ "app/api/auth/login/route.ts": login, "middleware.ts": "export { limiter as middleware } from './limiter';\n" });
    const custom = run({ "app/api/auth/login/route.ts": "import { guardLogin } from '@/lib/guard';\n" + login + "guardLogin();\n" }, { config: { rateLimiters: ["guardLogin"] } });
    for (const r of [inFile, inMiddleware, custom]) expect(of(r, "no-rate-limit")).toEqual([]);
  });
});

describe("deps-unpinned", () => {
  it("flags * and latest with the line of the dependency, and a missing lockfile", () => {
    const pkg = lines("{", '  "name": "x",', '  "dependencies": {', '    "stripe": "latest",', '    "next": "15.0.0",', '    "@supabase/supabase-js": "*"', "  }", "}");
    const r = run({ "package.json": pkg });
    const f = r.findings.filter((x) => x.rule === "deps-unpinned").sort((a, b) => a.line - b.line);
    expect(f.map((x) => [x.line, x.title])).toEqual([
      [1, "No lockfile"],
      [4, 'stripe is declared as "latest"'],
      [6, '@supabase/supabase-js is declared as "*"'],
    ]);
    expect(f.every((x) => x.severity === "low")).toBe(true);
  });

  it("finds the line of a package.json key written with JSON escapes", () => {
    const pkg = lines("{", '  "name": "x",', '  "dependencies": {', '    "st\\u0072ipe": "latest",', '    "a\\"b": "*"', "  }", "}");
    const f = run({ "package.json": pkg, "package-lock.json": "" }).findings.filter((x) => x.rule === "deps-unpinned").sort((a, b) => a.line - b.line);
    expect(f.map((x) => [x.line, x.title])).toEqual([
      [4, 'stripe is declared as "latest"'],
      [5, 'a"b is declared as "*"'],
    ]);
  });

  it("falls back to the line of the section when a dependency key is not in the line map", () => {
    const name = "x".repeat(300);
    const pkg = lines("{", '  "name": "x",', '  "dependencies": {', `    "${name}": "*"`, "  }", "}");
    const f = run({ "package.json": pkg, "package-lock.json": "" }).findings.filter((x) => x.rule === "deps-unpinned");
    expect(f.map((x) => x.line)).toEqual([3]);
  });

  it("is quiet for pinned versions with a lockfile (npm, pnpm, yarn or bun)", () => {
    for (const lock of ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]) {
      const r = run({ "package.json": '{ "name": "x", "dependencies": { "left-pad": "1.3.0" } }\n', [lock]: "" });
      expect(of(r, "deps-unpinned")).toEqual([]);
    }
  });

  it("only demands a lockfile at the project root, and ignores unparsable package.json files", () => {
    const r = run({ "packages/a/package.json": '{ "name": "a", "dependencies": { "x": "1.0.0" } }\n', "packages/b/package.json": "{ not json" });
    expect(of(r, "deps-unpinned")).toEqual([]);
  });
});
