import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { run as runCli, type Io } from "../src/cli.js";
import { collectProject } from "../src/project.js";
import { parseConfig } from "../src/config.js";
import { configLines } from "../src/report/common.js";
import { renderHuman } from "../src/report/human.js";
import { renderJson } from "../src/report/json.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { keys, run } from "./helpers.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-vis-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

function cli(args: string[]): { code: number; out: string; err: string } {
  let out = "";
  let err = "";
  const io: Io = { stdout: (t) => (out += t), stderr: (t) => (err += t), cwd: tmpdir(), color: false };
  return { code: runCli(args, io), out, err };
}

const OPEN = 'export async function GET() { return Response.json(await supabase.from("plans").select()); }\n';
const NO_RLS = "create table public.plans (id int);\n";

describe("what the config switched off is listed, not hidden", () => {
  it("moves ignoreRules findings to the not-counted list, naming the setting", () => {
    const r = run({ "supabase/migrations/001.sql": NO_RLS, "app/api/a/route.ts": OPEN }, { config: { ignoreRules: ["supabase-rls-missing"] } });
    expect(r.findings.map((f) => f.rule)).toEqual(["api-route-no-auth"]);
    expect(r.suppressed.map((f) => `${f.rule} (${f.suppressedBy})`)).toEqual(["supabase-rls-missing (config ignoreRules)"]);
  });

  it("does the same for publicRoutes", () => {
    const r = run({ "app/api/a/route.ts": OPEN }, { config: { publicRoutes: ["app/api/a/**"] } });
    expect(r.findings).toEqual([]);
    expect(r.suppressed.map((f) => `${f.rule} (${f.suppressedBy})`)).toEqual(["api-route-no-auth (config publicRoutes)"]);
  });

  it("keeps inline comments distinct from config settings", () => {
    const r = run({ "app/api/a/route.ts": `// saas-audit-ignore-file api-route-no-auth -- public price list\n${OPEN}` });
    expect(r.suppressed.map((f) => f.suppressedBy)).toEqual(["inline comment"]);
  });

  it("prints the effective config in all three formats, and says nothing when there is nothing to say", () => {
    const config = { ignoreRules: ["supabase-rls-missing"], publicRoutes: ["app/api/a/**"], authHelpers: ["myAuth"] };
    const r = audit(projectFromFilesWithSkipped(), { ...parseConfig("{}"), ...config }, { configSource: "saas-audit.config.json" });
    const human = renderHuman(r, { name: "x", version: "1", color: false });
    expect(human).toContain("Configuration in effect:");
    expect(human).toContain("  - settings from saas-audit.config.json");
    expect(human).toContain("  - rules switched off (ignoreRules): supabase-rls-missing");
    expect(human).toContain("  - routes treated as public (publicRoutes): app/api/a/**");
    const md = renderMarkdown(r, { name: "x", version: "1" });
    expect(md).toContain("**Configuration in effect.**");
    expect(md).toContain("- rules switched off (ignoreRules): supabase-rls-missing");
    expect(md).toContain("| `supabase-rls-missing` | Table created in a public-schema migration without ENABLE ROW LEVEL SECURITY. | switched off by config |");
    expect(md).toContain("| `api-route-no-auth` | Route handler or server action reads or writes data without a recognizable auth check. | applied |");
    const json = JSON.parse(renderJson(r, { name: "x", version: "1" }));
    expect(json.config).toMatchObject({ source: "saas-audit.config.json", ignoreRules: ["supabase-rls-missing"], publicRoutes: ["app/api/a/**"], authHelpers: ["myAuth"] });
    expect(configLines(run({}).config)).toEqual([]);
    expect(renderHuman(run({}), { name: "x", version: "1", color: false })).not.toContain("Configuration in effect");
  });

  it("counts what ignorePaths excluded", () => {
    const root = project({ "scripts/a.ts": "x", "scripts/b.ts": "x", "app/a.ts": "x", "app/a.test.ts": "x" });
    const config = parseConfig('{"ignorePaths":["scripts","**/*.test.ts"]}');
    const p = collectProject(root, config);
    expect(p.ignoredByConfigCount).toBe(2);
    expect(p.ignoredByConfig).toEqual(["app/a.test.ts", "scripts"]);
    const r = audit(p, config);
    expect(r.config.ignoredPathCount).toBe(2);
    expect(renderMarkdown(r, { name: "x", version: "1" })).toContain("- ignorePaths excluded 2 paths");
  });

  it("shows every not-counted finding in the terminal report, with what silenced it", () => {
    const r = run({ "app/api/a/route.ts": `// saas-audit-ignore-file all\n${OPEN}` });
    const text = renderHuman(r, { name: "x", version: "1", color: false });
    expect(text).toContain("1 finding not counted:");
    expect(text).toContain("  - high api-route-no-auth app/api/a/route.ts:2 (inline comment)");
  });
});

function projectFromFilesWithSkipped() {
  const root = project({ "supabase/migrations/001.sql": NO_RLS, "app/api/a/route.ts": OPEN });
  return collectProject(root, { ignorePaths: [] });
}

describe("directories skipped by name", () => {
  it("audits a route segment called build, out or dist, and only skips build output next to a package.json", () => {
    const root = project({
      "package.json": '{"name":"x"}',
      "app/api/build/route.ts": OPEN,
      "app/api/out/route.ts": OPEN,
      "lib/dist/db.ts": 'export const q = () => supabase.from("a").select();\n',
      "dist/server.js": OPEN,
      "build/out.js": OPEN,
      "coverage/lcov.js": OPEN,
      "node_modules/x/index.js": OPEN,
      ".next/server/a.js": OPEN,
    });
    const p = collectProject(root, { ignorePaths: [] });
    expect([...p.files.keys()].filter((f) => f.endsWith(".ts") || f.endsWith(".js")).sort()).toEqual(["app/api/build/route.ts", "app/api/out/route.ts", "lib/dist/db.ts"]);
    expect(p.skippedDirs.sort()).toEqual([".next", "build", "coverage", "dist", "node_modules"]);
    expect(keys(audit(p, parseConfig("{}")))).toEqual(["api-route-no-auth@app/api/build/route.ts:1", "api-route-no-auth@app/api/out/route.ts:1"]);
  });

  it("skips a package's own build output in a monorepo but not a sibling folder with the same name", () => {
    const root = project({ "apps/web/package.json": '{"name":"web"}', "apps/web/dist/a.js": "x", "apps/web/app/api/dist/route.ts": OPEN, "apps/web/.turbo/x.js": "x" });
    const p = collectProject(root, { ignorePaths: [] });
    expect(p.skippedDirs.sort()).toEqual(["apps/web/.turbo", "apps/web/dist"]);
    expect(p.files.has("apps/web/app/api/dist/route.ts")).toBe(true);
  });

  it("names the skipped directories in every report", () => {
    const root = project({ "package.json": '{"name":"x"}', "dist/a.js": "x", "lib/a.ts": "export const a = 1;\n" });
    const r = audit(collectProject(root, { ignorePaths: [] }), parseConfig("{}"));
    expect(renderMarkdown(r, { name: "x", version: "1" })).toContain("- directories skipped by name (dependencies and build output): dist");
    expect(renderHuman(r, { name: "x", version: "1", color: false })).toContain("directories skipped by name (dependencies and build output): dist");
    expect(JSON.parse(renderJson(r, { name: "x", version: "1" })).config.skippedDirs).toEqual(["dist"]);
  });

  it("says in the CLI report that a config excluded paths", () => {
    const root = project({ "saas-audit.config.json": '{"ignorePaths":["legacy"],"ignoreRules":["no-rate-limit"]}', "legacy/a.ts": OPEN, "lib/a.ts": "export const a = 1;\n" });
    const r = cli([root]);
    expect(r.out).toContain("settings from saas-audit.config.json");
    expect(r.out).toContain("ignorePaths excluded 1 path");
    expect(r.out).toContain("rules switched off (ignoreRules): no-rate-limit");
  });
});
