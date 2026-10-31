import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { run as runCli, type Io } from "../src/cli.js";
import { DEFAULT_CONFIG, ConfigError, parseConfig } from "../src/config.js";
import { GitIgnore, MAX_RULES } from "../src/gitignore.js";
import { compileGlobs, GlobError } from "../src/glob.js";
import { BudgetError, DEFAULT_LIMITS, tick, withBudget } from "../src/limits.js";
import { collectProject, projectFromFiles, readRegularFile } from "../src/project.js";
import { detectKeyShape } from "../src/rules/secrets.js";
import { foldConstant } from "../src/sql/model.js";
import { tokenize } from "../src/sql/tokenizer.js";
import { base64url, randomToken, run } from "./helpers.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try {
      chmodSync(d, 0o755);
    } catch {
      // already gone
    }
    rmSync(d, { recursive: true, force: true });
  }
});

function project(files: Record<string, string> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-limits-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

interface CliResult {
  code: number;
  out: string;
  err: string;
}

function cli(args: string[], cwd = tmpdir()): CliResult {
  let out = "";
  let err = "";
  const io: Io = { stdout: (t) => (out += t), stderr: (t) => (err += t), cwd, color: false };
  return { code: runCli(args, io), out, err };
}

/** Wall-clock milliseconds taken by `fn`. */
function ms(fn: () => unknown): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

describe("glob patterns from the repository", () => {
  it("matches the worst allowed patterns in well under a second", () => {
    const worst = compileGlobs(["*a".repeat(15) + "*b"]);
    expect(ms(() => worst("a".repeat(250) + ".ts"))).toBeLessThan(500);
    const stacked = compileGlobs(["**/".repeat(16) + "x"]);
    expect(ms(() => stacked(Array(300).fill("d").join("/") + "/y"))).toBeLessThan(500);
  });

  it("rejects what could blow up instead of compiling it", () => {
    expect(() => compileGlobs(["*a".repeat(127)])).toThrow(GlobError);
    expect(() => compileGlobs(["**/".repeat(40) + "x"])).toThrow(GlobError);
    expect(() => compileGlobs(["a".repeat(300)])).toThrow(GlobError);
  });

  it("treats an invalid character class as matching nothing, and an unterminated one as literal", () => {
    expect(compileGlobs(["[z-a]"])("m")).toBe(false);
    expect(compileGlobs(["[z-a]"])("z")).toBe(false);
    expect(compileGlobs(["a[b"])("a[b")).toBe(true);
    expect(compileGlobs(["[!a-c]x"])("dx")).toBe(true);
    expect(compileGlobs(["[!a-c]x"])("bx")).toBe(false);
  });

  it("is refused in the config with a clear message", () => {
    expect(() => parseConfig(JSON.stringify({ ignorePaths: ["*a".repeat(40)] }))).toThrow(ConfigError);
    expect(() => parseConfig(JSON.stringify({ publicRoutes: ["x".repeat(300)] }))).toThrow(/not usable \(longer than 256 characters\)/);
    expect(parseConfig(JSON.stringify({ ignorePaths: ["[z-a]"] })).ignorePaths).toEqual(["[z-a]"]);
  });

  it("skips .gitignore lines it will not compile, with a warning, and keeps the other rules", () => {
    const ig = new GitIgnore(new Map([[".gitignore", `${"*a".repeat(40)}\n.env*\n`]]));
    expect(ig.warnings).toEqual([".gitignore:1: pattern skipped (more than 16 wildcards)"]);
    expect(ig.isIgnored(".env.local")).toBe(true);
  });

  it("caps the number of rules per .gitignore", () => {
    const lines = Array.from({ length: MAX_RULES + 10 }, (_, i) => `f${i}.txt`).join("\n");
    const ig = new GitIgnore(new Map([[".gitignore", lines]]));
    expect(ig.warnings).toHaveLength(1);
    expect(ig.warnings[0]).toContain(`more than ${MAX_RULES} rules`);
    expect(ig.isIgnored("f10.txt")).toBe(true);
    expect(ig.isIgnored(`f${MAX_RULES + 5}.txt`)).toBe(false);
  });

  it("does not stall on a .gitignore or .env line made of whitespace", () => {
    const spaces = " ".repeat(200_000);
    const t = ms(() => run({ ".env.local": `A_SECRET=x${spaces}y\n`, ".gitignore": `foo${spaces}x\n` }));
    expect(t).toBeLessThan(1500);
  });
});

describe("linear-time secret and SQL scans", () => {
  it("scans repeated database-URL and JWT prefixes in linear time", () => {
    const urls = "postgres://x:".repeat(10_000);
    const jwts = "-eyJaaaaaaaa".repeat(11_000);
    expect(ms(() => detectKeyShape(urls))).toBeLessThan(500);
    expect(ms(() => detectKeyShape(jwts))).toBeLessThan(500);
  });

  it("still finds a database URL and a service-role JWT inside long strings", () => {
    const pad = "a ".repeat(5000);
    expect(detectKeyShape(`${pad}postgres://app:${randomToken(20, 31)}@db.example.test/app`)).toMatchObject({ severity: "high" });
    const jwt = `${base64url({ alg: "HS256" })}.${base64url({ role: "service_role" })}.${randomToken(43, 32)}`;
    expect(detectKeyShape(`${pad}${jwt}`)).toMatchObject({ severity: "critical" });
  });

  it("folds a 100 000-deep parenthesised policy expression in linear time", () => {
    const toks = tokenize("(".repeat(100_000) + "true" + ")".repeat(100_000));
    expect(ms(() => expect(foldConstant(toks)).toBe("true"))).toBeLessThan(500);
  });

  it("handles a migration with 20 000 policies and 8 000 findings in one file without quadratic cost", () => {
    const sql = "create table public.t (id int, user_id uuid);\nalter table public.t enable row level security;\n" + Array.from({ length: 20_000 }, (_, i) => `create policy p${i} on public.t for select to authenticated using (auth.uid() = user_id);`).join("\n");
    expect(ms(() => run({ "supabase/migrations/001.sql": sql }))).toBeLessThan(3000);
    const tables = Array.from({ length: 8000 }, (_, i) => `create table public.t${i} (id int);`).join("\n");
    expect(ms(() => expect(run({ "supabase/migrations/001.sql": tables }).findings).toHaveLength(8000))).toBeLessThan(3000);
  });

  it("applies create/drop policy pairs in constant time each", () => {
    const sql = "create table public.t (id int);\nalter table public.t enable row level security;\n" + Array.from({ length: 30_000 }, (_, i) => `create policy p${i} on public.t using (true);\ndrop policy p${i} on public.t;`).join("\n");
    expect(ms(() => run({ "supabase/migrations/001.sql": sql }))).toBeLessThan(3000);
  });

  it("handles a server-action file with thousands of exports without quadratic cost", () => {
    const body = Array.from({ length: 3000 }, (_, i) => `export async function a${i}(id: string) { await supabase.from("t").delete().eq("id", id); }`).join("\n");
    const r = run({ "app/actions.ts": `"use server";\n${body}\n` });
    expect(r.findings.length).toBe(6000);
    expect(ms(() => run({ "app/actions.ts": `"use server";\n${body}\n` }))).toBeLessThan(5000);
  });

  it("does not turn a very long member chain into quadratic work", () => {
    const text = `export async function GET(req: Request) { const x = req${".search".repeat(900)}; return Response.json(x); }\n`;
    expect(ms(() => run({ "app/api/a/route.ts": text }))).toBeLessThan(1000);
  });
});

describe("hostile nesting", () => {
  const route = (expr: string) => `export async function GET() { return Response.json(${expr}); }\n`;

  it("skips a deeply parenthesised file, says so, and still audits the others", () => {
    const r = run({
      "app/api/deep/route.ts": route("(".repeat(5000) + "1" + ")".repeat(5000)),
      "app/api/ok/route.ts": 'export async function GET() { return Response.json(await supabase.from("a").select()); }\n',
    });
    expect(r.skipped).toHaveLength(1);
    expect(r.skipped[0]).toMatch(/^app\/api\/deep\/route\.ts: not analysed: syntax tree nests (?:deeper than 1000 levels|too deeply to parse)$/);
    expect(r.findings.map((f) => f.file)).toEqual(["app/api/ok/route.ts"]);
  });

  it.each([
    ["binary chain", `const x = ${Array(20_000).fill("a").join("+")};`],
    ["call chain", `const x = req${".a()".repeat(4000)};`],
    ["nested arrays", `const x = ${"[".repeat(20_000)}${"]".repeat(20_000)};`],
    ["nested ternaries", `const x = ${"a ? b : ".repeat(5000)}c;`],
  ])("does not crash on a %s", (_name, body) => {
    const r = run({ "app/api/a/route.ts": `export async function GET(req: Request) { ${body} return Response.json(1); }\n` });
    expect(Array.isArray(r.findings)).toBe(true);
    expect(r.skipped.length).toBeLessThanOrEqual(1);
  });

  it("analyses a file whose syntax tree is deep but within the limit", () => {
    const terms = Array(950).fill("a").join(" + ");
    const r = run({ "app/api/a/route.ts": `export async function GET(req: Request) { const a = req.url; const x = ${terms}; return Response.json({ x, rows: await supabase.from("a").select() }); }\n` });
    expect(r.skipped).toEqual([]);
    expect(r.findings.map((f) => f.rule)).toEqual(["api-route-no-auth"]);
  });

  it("does not misjudge a policy whose conditions are nested too deeply to fold", () => {
    const expr = "not ".repeat(80) + "false";
    const r = run({ "supabase/migrations/001.sql": `create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy p on public.t for select using (${expr});\n` });
    const f = r.findings.find((x) => x.rule === "supabase-policy-permissive")!;
    expect(f.severity).toBe("medium");
    expect(f.title).toContain("nested too deeply to analyse");
  });
});

describe("time budgets", () => {
  it("raises BudgetError from tick() once the deadline has passed", () => {
    expect(() =>
      withBudget(-1, () => {
        for (let i = 0; i < 1000; i++) tick();
      }),
    ).toThrow(BudgetError);
    expect(() => {
      for (let i = 0; i < 1000; i++) tick();
    }).not.toThrow();
  });

  it("records a file whose analysis runs out of time as skipped and carries on", () => {
    const many = Array.from({ length: 600 }, (_, i) => `export const v${i} = ${i};`).join("\n");
    const r = audit(projectFromFiles({ "lib/big.ts": many, "app/api/a/route.ts": 'export async function GET() { return Response.json(await supabase.from("a").select()); }\n' }), DEFAULT_CONFIG, { limits: { fileBudgetMs: -1 } });
    expect(r.skipped.some((s) => s.startsWith("app/api/a/route.ts: analysis stopped: time budget exceeded"))).toBe(true);
    expect(Array.isArray(r.findings)).toBe(true);
  });

  it("stops everything when the total budget is gone", () => {
    const many = Array.from({ length: 600 }, (_, i) => `export const v${i} = ${i};`).join("\n");
    const r = audit(projectFromFiles({ "lib/big.ts": many }), DEFAULT_CONFIG, { limits: { totalBudgetMs: -1 } });
    expect(r.skipped.length).toBeGreaterThan(0);
  });
});

describe("reading a hostile directory tree", () => {
  it("skips an oversize file, a symlink and a FIFO without reading or blocking on them", () => {
    const root = project({ "ok.ts": "export const a = 1;" });
    writeFileSync(join(root, "big.ts"), "a".repeat(DEFAULT_LIMITS.maxFileBytes + 1));
    symlinkSync("/etc/hostname", join(root, "link.ts"));
    execFileSync("mkfifo", [join(root, "pipe.ts")]);
    const t = ms(() => {
      const p = collectProject(root, { ignorePaths: [] });
      expect([...p.files.keys()]).toEqual(["ok.ts"]);
      expect(p.skipped).toEqual(["big.ts: not read, larger than 1048576 bytes"]);
      expect(p.warnings).toEqual(["1 symbolic link was not followed: link.ts"]);
    });
    expect(t).toBeLessThan(1000);
  });

  it("does not block when a path is a FIFO at the moment it is opened", () => {
    const root = project();
    execFileSync("mkfifo", [join(root, "x.ts")]);
    expect(ms(() => expect(readRegularFile(join(root, "x.ts"), 1024)).toEqual({ skip: "not a regular file" }))).toBeLessThan(500);
  });

  it("does not follow a symlink that replaced a file after the directory was listed", () => {
    const root = project({ "secret.txt": "top secret" });
    symlinkSync(join(root, "secret.txt"), join(root, "a.ts"));
    expect(readRegularFile(join(root, "a.ts"), 1024)).toEqual({ skip: "could not be opened (ELOOP)" });
  });

  it("records unreadable files and directories instead of crashing", () => {
    if (process.getuid?.() === 0) return;
    const root = project({ "ok.ts": "export const a = 1;", "locked.ts": "x", "sub/a.ts": "x" });
    chmodSync(join(root, "locked.ts"), 0o000);
    chmodSync(join(root, "sub"), 0o000);
    const p = collectProject(root, { ignorePaths: [] });
    expect([...p.files.keys()]).toEqual(["ok.ts"]);
    expect(p.skipped).toEqual(["locked.ts: not read, could not be opened (EACCES)", "sub: directory could not be read (EACCES)"]);
    chmodSync(join(root, "sub"), 0o755);
  });

  it("stops at the file-count and total-size limits and says that it did", () => {
    const root = project({ "a.ts": "x", "b.ts": "x", "c.ts": "x", "d.ts": "x" });
    const byCount = collectProject(root, { ignorePaths: [] }, { ...DEFAULT_LIMITS, maxFiles: 2 });
    expect([...byCount.files.keys()]).toEqual(["a.ts", "b.ts"]);
    expect(byCount.skipped).toEqual(["c.ts: not read, the limit of 2 files was reached (further files are not listed)"]);
    const bySize = collectProject(root, { ignorePaths: [] }, { ...DEFAULT_LIMITS, maxTotalBytes: 2 });
    expect([...bySize.files.keys()]).toEqual(["a.ts", "b.ts"]);
    expect(bySize.skipped[0]).toContain("the limit of 2 bytes in total was reached");
  });

  it("stops at the directory depth limit", () => {
    const root = project({ "a/b/c/d/e.ts": "x", "top.ts": "x" });
    const p = collectProject(root, { ignorePaths: [] }, { ...DEFAULT_LIMITS, maxDirDepth: 2 });
    expect([...p.files.keys()]).toEqual(["top.ts"]);
    expect(p.skipped).toEqual(["a/b/c: directory nests deeper than 2 levels"]);
  });
});

describe("the config file in a hostile repository", () => {
  it("refuses a config that is a symlink to /dev/zero without reading it", () => {
    const root = project();
    symlinkSync("/dev/zero", join(root, "saas-audit.config.json"));
    let result: CliResult | undefined;
    expect(ms(() => (result = cli([root])))).toBeLessThan(1000);
    expect(result!.code).toBe(2);
    expect(result!.err).toContain("saas-audit.config.json: could not be opened (ELOOP)");
  });

  it("does not leak the first characters of a file the config symlink points at", () => {
    const outside = project({ "secret.txt": "TOP-SECRET-VALUE not json" });
    const root = project();
    symlinkSync(join(outside, "secret.txt"), join(root, "saas-audit.config.json"));
    const r = cli([root]);
    expect(r.code).toBe(2);
    expect(r.err).not.toContain("TOP-SECRET");
  });

  it("refuses a directory with the config's name and a config that is too large", () => {
    const dirRoot = project();
    mkdirSync(join(dirRoot, "saas-audit.config.json"));
    expect(cli([dirRoot]).err).toContain("saas-audit.config.json: not a regular file");
    const big = project({ "saas-audit.config.json": `{"ignoreRules":[${'"x",'.repeat(300_000)}"x"]}` });
    expect(cli([big]).err).toContain("larger than 1048576 bytes");
  });

  it("does not echo what a malformed config contains", () => {
    const root = project({ "saas-audit.config.json": "TOP-SECRET-LOOKING { not json" });
    const r = cli([root]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/^saas-audit\.config\.json: invalid JSON(?: \(at position \d+\))?\n/);
    expect(r.err).not.toContain("TOP-SECRET");
  });

  it("still follows a symlink given explicitly with --config, because that is the user's own choice", () => {
    const root = project({ "real.json": '{"ignoreRules":["no-rate-limit"]}' });
    symlinkSync(join(root, "real.json"), join(root, "alias.json"));
    expect(cli([root, "--config", join(root, "alias.json")]).code).toBe(0);
  });

  it("does not trust a .git that is a symlink", () => {
    const outside = project();
    mkdirSync(join(outside, "fake"));
    const root = project({ "a.ts": "x" });
    symlinkSync(join(outside, "fake"), join(root, ".git"));
    const p = collectProject(root, { ignorePaths: [] });
    expect(p.gitTracked).toBeNull();
    expect(p.warnings.some((w) => w.includes(".git is not a plain directory"))).toBe(true);
  });
});

describe("incomplete audits fail closed", () => {
  const BIG = "a".repeat(DEFAULT_LIMITS.maxFileBytes + 1);

  it("exits 3 when a file was skipped, prints it, and marks the JSON incomplete", () => {
    const root = project({ "app/big.ts": BIG });
    const r = cli([root]);
    expect(r.code).toBe(3);
    expect(r.out).toContain("Not analysed (1): this audit is incomplete.");
    expect(r.out).toContain("app/big.ts: not read, larger than 1048576 bytes");
    expect(r.err).toContain("audit incomplete: 1 item was not analysed (exit code 3");
    const json = JSON.parse(cli([root, "--json"]).out);
    expect(json.complete).toBe(false);
    expect(json.skipped).toEqual(["app/big.ts: not read, larger than 1048576 bytes"]);
    expect(cli([root, "--markdown"]).out).toContain("**This audit is incomplete.**");
  });

  it("exits 1 for findings before it exits 3, and 0 with --allow-incomplete or --fail-on none only for what they cover", () => {
    const root = project({ "app/big.ts": BIG, "supabase/migrations/001.sql": "create table public.t (id int);\n" });
    expect(cli([root]).code).toBe(1);
    const clean = project({ "app/big.ts": BIG });
    expect(cli([clean, "--allow-incomplete"]).code).toBe(0);
    expect(cli([clean, "--fail-on", "none"]).code).toBe(3);
    expect(cli([clean, "--fail-on", "none", "--allow-incomplete"]).code).toBe(0);
  });
});

describe("unexpected failures", () => {
  it("are reported as an internal error with exit code 2 and no stack trace", () => {
    const root = project({ "a.ts": "export const a = 1;\n" });
    const r = cli([root, "--markdown", "--output", join(root, "missing-dir", "out.md")]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/^saas-audit: internal error: Error: ENOENT/);
    expect(r.err).not.toContain("    at ");
  });
});
