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

/** An 8x larger input may cost at most this many times the CPU time of the small one: linear is about 8, quadratic about 64. */
const MAX_GROWTH = 24;

/**
 * CPU microseconds of the calling thread. Not the whole process: V8's parallel garbage-collector threads spin while waiting when the
 * machine is oversubscribed, which inflates process-wide CPU time for allocation-heavy (larger) inputs and has nothing to do with the code.
 */
function threadCpuMicros(): number {
  const used = typeof process.threadCpuUsage === "function" ? process.threadCpuUsage() : process.cpuUsage();
  return used.user + used.system;
}

/** CPU milliseconds used by `fn`; the best of five runs, so a busy machine does not inflate it. */
function cpuMs(fn: () => unknown): number {
  let best = Infinity;
  for (let i = 0; i < 5; i++) {
    const before = threadCpuMicros();
    fn();
    best = Math.min(best, (threadCpuMicros() - before) / 1000);
  }
  return best;
}

/**
 * CPU time of `fn` on `make(8 * n)` divided by its CPU time on `make(n)`. Unlike a wall-clock cap this does not depend on how fast or
 * busy the machine is. The small time is floored at 10 ms so timer granularity and one-off hiccups cannot inflate the ratio.
 */
function growth<T>(make: (size: number) => T, n: number, fn: (input: T) => unknown): number {
  const small = make(n);
  const large = make(8 * n);
  fn(small);
  return cpuMs(() => fn(large)) / Math.max(cpuMs(() => fn(small)), 10);
}

describe("glob patterns from the repository", () => {
  it("matches the worst allowed patterns in well under a second", { timeout: 60_000 }, () => {
    const worst = compileGlobs(["*a".repeat(15) + "*b"]);
    const many = (match: (path: string) => boolean, path: string) => {
      for (let i = 0; i < 200; i++) match(path);
    };
    expect(worst("a".repeat(250) + ".ts")).toBe(false);
    expect(growth((n) => "a".repeat(n) + ".ts", 31, (path) => many(worst, path))).toBeLessThan(MAX_GROWTH);
    const stacked = compileGlobs(["**/".repeat(16) + "x"]);
    expect(stacked(Array(300).fill("d").join("/") + "/y")).toBe(false);
    expect(growth((n) => Array(n).fill("d").join("/") + "/y", 38, (path) => many(stacked, path))).toBeLessThan(MAX_GROWTH);
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

  it("does not stall on a .gitignore or .env line made of whitespace", { timeout: 60_000 }, () => {
    const files = (n: number) => ({ ".env.local": `A_SECRET=x${" ".repeat(n)}y\n`, ".gitignore": `foo${" ".repeat(n)}x\n` });
    expect(growth(files, 50_000, (f) => run(f))).toBeLessThan(MAX_GROWTH);
  });
});

describe("linear-time secret and SQL scans", () => {
  it("scans repeated database-URL and JWT prefixes in linear time", { timeout: 60_000 }, () => {
    expect(growth((n) => "postgres://x:".repeat(n), 2500, (s) => detectKeyShape(s))).toBeLessThan(MAX_GROWTH);
    expect(growth((n) => "-eyJaaaaaaaa".repeat(n), 2750, (s) => detectKeyShape(s))).toBeLessThan(MAX_GROWTH);
  });

  it("still finds a database URL and a service-role JWT inside long strings", () => {
    const pad = "a ".repeat(5000);
    expect(detectKeyShape(`${pad}postgres://app:${randomToken(20, 31)}@db.example.test/app`)).toMatchObject({ severity: "high" });
    const jwt = `${base64url({ alg: "HS256" })}.${base64url({ role: "service_role" })}.${randomToken(43, 32)}`;
    expect(detectKeyShape(`${pad}${jwt}`)).toMatchObject({ severity: "critical" });
  });

  it("folds a 100 000-deep parenthesised policy expression in linear time", { timeout: 60_000 }, () => {
    const toks = (n: number) => tokenize("(".repeat(n) + "true" + ")".repeat(n));
    expect(foldConstant(toks(100_000))).toBe("true");
    expect(growth(toks, 25_000, (t) => foldConstant(t))).toBeLessThan(MAX_GROWTH);
  });

  it("handles a migration with 20 000 policies and 8 000 findings in one file without quadratic cost", { timeout: 60_000 }, () => {
    const sql = (n: number) => "create table public.t (id int, user_id uuid);\nalter table public.t enable row level security;\n" + Array.from({ length: n }, (_, i) => `create policy p${i} on public.t for select to authenticated using (auth.uid() = user_id);`).join("\n");
    expect(growth((n) => ({ "supabase/migrations/001.sql": sql(n) }), 5000, (f) => run(f))).toBeLessThan(MAX_GROWTH);
    const tables = (n: number) => Array.from({ length: n }, (_, i) => `create table public.t${i} (id int);`).join("\n");
    expect(run({ "supabase/migrations/001.sql": tables(8000) }).findings).toHaveLength(8000);
    expect(growth((n) => ({ "supabase/migrations/001.sql": tables(n) }), 4000, (f) => run(f))).toBeLessThan(MAX_GROWTH);
  });

  it("applies create/drop policy pairs in constant time each", { timeout: 60_000 }, () => {
    const sql = (n: number) => "create table public.t (id int);\nalter table public.t enable row level security;\n" + Array.from({ length: n }, (_, i) => `create policy p${i} on public.t using (true);\ndrop policy p${i} on public.t;`).join("\n");
    expect(growth((n) => ({ "supabase/migrations/001.sql": sql(n) }), 3750, (f) => run(f))).toBeLessThan(MAX_GROWTH);
  });

  // Auditing is linear (best-of-6 CPU time about 0.2 ms per action: 1000 to 16 000 actions doubled the time with each doubling),
  // so 3000 actions take under a second of CPU. A wall-clock cap of 5 s failed on a shared CI runner that was several times slower than
  // that, which says nothing about the tool. Quadratic work is caught by comparing CPU time for N and 8N actions instead
  // (linear: about 8x, quadratic: about 64x), and the test timeout is generous so a busy runner cannot fail it.
  it("handles a server-action file with thousands of exports without quadratic cost", { timeout: 60_000 }, () => {
    const files = (n: number) => ({
      "app/actions.ts": `"use server";\n${Array.from({ length: n }, (_, i) => `export async function a${i}(id: string) { await supabase.from("t").delete().eq("id", id); }`).join("\n")}\n`,
    });
    expect(run(files(3000)).findings.length).toBe(6000);
    expect(growth(files, 300, (f) => run(f))).toBeLessThan(MAX_GROWTH);
  });

  it("does not turn a very long member chain into quadratic work", { timeout: 60_000 }, () => {
    const text = (n: number) => `export async function GET(req: Request) { const x = req${".search".repeat(n)}; return Response.json(x); }\n`;
    expect(growth((n) => ({ "app/api/a/route.ts": text(n) }), 112, (f) => run(f))).toBeLessThan(MAX_GROWTH);
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
  it("skips an oversize file, a symlink and a FIFO without reading or blocking on them", { timeout: 20_000 }, () => {
    const root = project({ "ok.ts": "export const a = 1;" });
    writeFileSync(join(root, "big.ts"), "a".repeat(DEFAULT_LIMITS.maxFileBytes + 1));
    symlinkSync("/etc/hostname", join(root, "link.ts"));
    execFileSync("mkfifo", [join(root, "pipe.ts")]);
    const p = collectProject(root, { ignorePaths: [] });
    expect([...p.files.keys()]).toEqual(["ok.ts"]);
    expect(p.skipped).toEqual(["big.ts: not read, larger than 1048576 bytes"]);
    expect(p.warnings).toEqual(["1 symbolic link was not followed: link.ts"]);
  });

  it("does not block when a path is a FIFO at the moment it is opened", { timeout: 20_000 }, () => {
    const root = project();
    execFileSync("mkfifo", [join(root, "x.ts")]);
    expect(readRegularFile(join(root, "x.ts"), 1024)).toEqual({ skip: "not a regular file" });
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
  // A hang is caught by the explicit test timeout; a wall-clock cap on a loaded machine only produces false failures.
  it("refuses a config that is a symlink to /dev/zero without reading it", { timeout: 20_000 }, () => {
    const root = project();
    symlinkSync("/dev/zero", join(root, "saas-audit.config.json"));
    const result = cli([root]);
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
