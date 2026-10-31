import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RULES } from "../src/catalog.js";
import { run, type Io } from "../src/cli.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-cli-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

function cli(args: string[], cwd: string): { code: number; out: string; err: string } {
  let out = "";
  let err = "";
  const io: Io = { stdout: (t) => (out += t), stderr: (t) => (err += t), cwd, color: false };
  const code = run(args, io);
  return { code, out, err };
}

const OPEN_ROUTE = { "app/api/notes/route.ts": 'export async function GET() {\n  const { data } = await supabase.from("notes").select("*");\n  return Response.json(data);\n}\n' };
const MISSING_RLS = { "supabase/migrations/001.sql": "create table public.notes (id int);\n" };

describe("cli: information flags", () => {
  it("prints usage with --help and the version with --version", () => {
    const h = cli(["--help"], tmpdir());
    expect(h.code).toBe(0);
    expect(h.out).toContain("Usage: saas-audit [dir] [options]");
    expect(h.out).toContain("--markdown");
    const v = cli(["--version"], tmpdir());
    expect(v.code).toBe(0);
    expect(v.out).toMatch(/^\d+\.\d+\.\d+\n$/);
  });

  it("lists every rule with --list-rules", () => {
    const l = cli(["--list-rules"], tmpdir());
    expect(l.code).toBe(0);
    for (const r of RULES) expect(l.out).toContain(r.id);
    expect(l.out.trim().split("\n")).toHaveLength(RULES.length);
  });
});

describe("cli: usage errors exit 2", () => {
  it.each([
    ["an unknown option", ["--nope"]],
    ["a bad severity", ["--min-severity", "urgent"]],
    ["a bad fail-on", ["--fail-on", "urgent"]],
    ["a missing value", ["--output"]],
    ["a bad date", ["--date", "yesterday"]],
    ["two directories", ["a", "b"]],
    ["--json with --markdown", ["--json", "--markdown"]],
  ])("rejects %s", (_name, args) => {
    const r = cli(args, tmpdir());
    expect(r.code).toBe(2);
    expect(r.err).toContain("Usage:");
  });

  it("rejects a directory that does not exist", () => {
    const r = cli(["/definitely/not/here"], tmpdir());
    expect(r.code).toBe(2);
    expect(r.err).toContain("not a directory");
  });

  it("rejects an invalid config and a missing explicit config", () => {
    const root = project({ "saas-audit.config.json": '{"authHelper":["x"]}' });
    const bad = cli([root], tmpdir());
    expect(bad.code).toBe(2);
    expect(bad.err).toContain('unknown key "authHelper"');
    const missing = cli([root, "--config", "nope.json"], tmpdir());
    expect(missing.code).toBe(2);
    expect(missing.err).toContain("config file not found");
  });
});

describe("cli: exit codes and filters", () => {
  it("exits 1 when there are findings and 0 when there are none", () => {
    expect(cli([project(OPEN_ROUTE)], tmpdir()).code).toBe(1);
    expect(cli([project({ "lib/a.ts": "export const x = 1;\n" })], tmpdir()).code).toBe(0);
  });

  it("applies --fail-on to the exit code only", () => {
    const root = project(MISSING_RLS); // one high finding
    expect(cli([root, "--fail-on", "critical"], tmpdir()).code).toBe(0);
    expect(cli([root, "--fail-on", "high"], tmpdir()).code).toBe(1);
    expect(cli([root, "--fail-on", "none"], tmpdir()).code).toBe(0);
    expect(cli([root, "--fail-on", "critical"], tmpdir()).out).toContain("supabase-rls-missing");
  });

  it("hides findings below --min-severity and does not fail on them", () => {
    const root = project({ ...MISSING_RLS, "next.config.mjs": "export default {};\n" }); // high + info
    const all = cli([root, "--json"], tmpdir());
    expect(JSON.parse(all.out).summary.total).toBe(2);
    const high = cli([root, "--json", "--min-severity", "high"], tmpdir());
    expect(JSON.parse(high.out).summary.total).toBe(1);
    const none = cli([project({ "next.config.mjs": "export default {};\n" }), "--min-severity", "low"], tmpdir());
    expect(none.code).toBe(0);
  });

  it("resolves the directory against the working directory and defaults to it", () => {
    const root = project(OPEN_ROUTE);
    expect(cli([], root).code).toBe(1);
    expect(cli(["."], root).code).toBe(1);
  });
});

describe("cli: output formats", () => {
  it("prints the human report by default, JSON with --json and Markdown with --markdown", () => {
    const root = project(OPEN_ROUTE);
    expect(cli([root], tmpdir()).out).toContain("api-route-no-auth  app/api/notes/route.ts:1");
    const json = JSON.parse(cli([root, "--json"], tmpdir()).out);
    expect(json.findings[0].rule).toBe("api-route-no-auth");
    expect(json.project).toMatch(/^saas-audit-cli-/);
    const md = cli([root, "--markdown", "--date", "2026-01-31"], tmpdir()).out;
    expect(md).toContain("# Security audit report:");
    expect(md).toContain("on 2026-01-31.");
    expect(md).toContain("### SA-001:");
  });

  it("writes to --output and says so on stderr instead of printing the report", () => {
    const root = project(OPEN_ROUTE);
    const out = join(root, "report.md");
    const r = cli([root, "--markdown", "-o", out], tmpdir());
    expect(r.out).toBe("");
    expect(r.err).toBe(`wrote ${out}\n`);
    expect(readFileSync(out, "utf8")).toContain("## What was not checked");
  });

  it("reads saas-audit.config.json from the audited directory, or --config from elsewhere", () => {
    const root = project({ ...OPEN_ROUTE, "saas-audit.config.json": '{"authHelpers":["assertMember"],"publicRoutes":["app/api/notes/**"]}' });
    expect(cli([root], tmpdir()).code).toBe(0);
    const other = project(OPEN_ROUTE);
    const cfg = project({ "c.json": '{"publicRoutes":["app/api/notes/**"]}' });
    expect(cli([other, "--config", join(cfg, "c.json")], tmpdir()).code).toBe(0);
    expect(cli([other], tmpdir()).code).toBe(1);
  });

  it("is deterministic: two runs print the same bytes", () => {
    const root = project({ ...OPEN_ROUTE, ...MISSING_RLS });
    expect(cli([root, "--markdown"], tmpdir()).out).toBe(cli([root, "--markdown"], tmpdir()).out);
    expect(cli([root, "--json"], tmpdir()).out).toBe(cli([root, "--json"], tmpdir()).out);
  });
});
