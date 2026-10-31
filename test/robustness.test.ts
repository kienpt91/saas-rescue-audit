import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { collectProject } from "../src/project.js";
import { keys, run } from "./helpers.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function onDisk(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-robust-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

describe("robustness", () => {
  it("audits an empty project without findings and says what it could not assess", () => {
    const r = run({});
    expect(r.findings).toEqual([]);
    expect(r.notes).toHaveLength(3);
    expect(r.notes[0]).toContain("No Supabase SQL files found");
  });

  it("does not throw on syntactically broken TypeScript, TSX or SQL", () => {
    const r = run({
      "app/api/a/route.ts": "export async function GET( {\n  const x = await supabase.from(\n",
      "components/B.tsx": "export const B = () => <div dangerouslySetInnerHTML={{ __html: }} />;\n",
      "supabase/migrations/001.sql": "create table public.t (id int,\ncreate policy p on\nalter table",
    });
    expect(Array.isArray(r.findings)).toBe(true);
  });

  it("reports the same lines for CRLF files as for LF files", () => {
    const lf = "create table public.a (id int);\ncreate table public.b (id int);\n";
    const crlf = lf.replace(/\n/g, "\r\n");
    expect(keys(run({ "supabase/migrations/001.sql": crlf }))).toEqual(keys(run({ "supabase/migrations/001.sql": lf })));
    const ts = 'export async function GET() {\n  await supabase.from("a").delete();\n}\n';
    expect(keys(run({ "app/api/a/route.ts": ts.replace(/\n/g, "\r\n") }))).toEqual(keys(run({ "app/api/a/route.ts": ts })));
  });

  it("ignores a UTF-8 byte order mark at the start of a file", () => {
    const root = onDisk({ "supabase/migrations/001.sql": "\uFEFFcreate table public.a (id int);\n", ".env.local": "\uFEFFA_SECRET=1234\n" });
    const project = collectProject(root, { ignorePaths: [] });
    const r = audit(project, DEFAULT_CONFIG);
    expect(r.findings.map((f) => f.rule).sort()).toEqual(["secret-committed-env", "supabase-rls-missing"]);
    expect(r.findings.find((f) => f.rule === "secret-committed-env")!.evidence).toBe("A_SECRET=…");
  });

  it("gives the same answer however many times it runs and in which order files were added", () => {
    const files = {
      "supabase/migrations/001.sql": "create table public.a (id int);",
      "app/api/a/route.ts": 'export async function GET() { return Response.json(await supabase.from("a").select()); }',
      "next.config.mjs": "export default {};",
    };
    const reversed = Object.fromEntries(Object.entries(files).reverse());
    expect(JSON.stringify(run(files).findings)).toBe(JSON.stringify(run(reversed).findings));
    expect(JSON.stringify(run(files).findings)).toBe(JSON.stringify(run(files).findings));
  });

  it("recognises a route handler exported as a const arrow function, and via a default-wrapped pages handler", () => {
    const arrow = run({ "app/api/a/route.ts": 'export const GET = async () => Response.json(await supabase.from("a").select());\n' });
    const wrapped = run({ "pages/api/a.ts": 'export default withLogging(async function handler(req, res) { res.json(await supabase.from("a").select()); });\n' });
    expect(keys(arrow)).toEqual(["api-route-no-auth@app/api/a/route.ts:1"]);
    expect(arrow.findings[0]!.evidence.split("\n")).toHaveLength(1);
    expect(keys(wrapped)).toEqual(["api-route-no-auth@pages/api/a.ts:1"]);
  });

  it("does not mistake property names such as constructor or toString for configuration keys", () => {
    const r = run({ "app/api/a/route.ts": 'export async function constructor() {}\nexport const toString = () => supabase.from("a").select();\n' });
    expect(r.findings).toEqual([]);
  });

  it("uses a single route key: a file outside app/ or pages/api is not a route", () => {
    const r = run({ "src/handlers/route.ts": 'export async function GET() { return supabase.from("a").delete(); }\n' });
    expect(r.findings).toEqual([]);
  });

  it("understands the src/ layout", () => {
    const r = run({ "src/app/api/a/route.ts": 'export async function GET() { return Response.json(await supabase.from("a").select()); }\n' });
    expect(keys(r)).toEqual(["api-route-no-auth@src/app/api/a/route.ts:1"]);
  });
});
