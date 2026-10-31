import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigError, DEFAULT_CONFIG, parseConfig } from "../src/config.js";
import { GitIgnore } from "../src/gitignore.js";
import { parseGitIndex } from "../src/gitindex.js";
import { compileGlobs } from "../src/glob.js";
import { GlobError } from "../src/glob.js";
import { DEFAULT_LIMITS } from "../src/limits.js";
import { collectProject } from "../src/project.js";
import { applySuppressions, parseDirectives } from "../src/suppress.js";
import type { Finding } from "../src/types.js";
import { buildIndex } from "./git-index.js";

describe("globs", () => {
  it("matches ** across zero or more directories", () => {
    const match = compileGlobs(["**/*.test.ts"]);
    expect(match("a.test.ts")).toBe(true);
    expect(match("src/deep/a.test.ts")).toBe(true);
    expect(match("src/a.ts")).toBe(false);
  });

  it("matches a directory pattern against everything below it, but only at the root", () => {
    const match = compileGlobs(["scripts"]);
    expect(match("scripts")).toBe(true);
    expect(match("scripts/seed.ts")).toBe(true);
    expect(match("src/scripts/seed.ts")).toBe(false);
  });

  it("supports ? and character classes and keeps * inside one segment", () => {
    const match = compileGlobs(["app/api/v?/[ab]*/route.ts"]);
    expect(match("app/api/v1/alpha/route.ts")).toBe(true);
    expect(match("app/api/v2/cat/route.ts")).toBe(false);
    expect(match("app/api/v1/a/b/route.ts")).toBe(false);
  });

  it("rejects patterns that are too long or have too many wildcards instead of compiling them", () => {
    expect(() => compileGlobs(["*".repeat(300)])).toThrow(GlobError);
    expect(() => compileGlobs(["*a".repeat(20)])).toThrow(GlobError);
    expect(() => compileGlobs(["*a".repeat(8)])).not.toThrow();
  });
});

describe("gitignore", () => {
  it("ignores .env variants and honours a negation for the example file", () => {
    const ig = new GitIgnore(new Map([[".gitignore", ".env*\n!.env.example\n"]]));
    expect(ig.isIgnored(".env")).toBe(true);
    expect(ig.isIgnored(".env.local")).toBe(true);
    expect(ig.isIgnored(".env.example")).toBe(false);
  });

  it("treats a trailing slash as directory-only and matches at any depth", () => {
    const ig = new GitIgnore(new Map([[".gitignore", "cache/\n"]]));
    expect(ig.isIgnored("cache/a.txt")).toBe(true);
    expect(ig.isIgnored("src/cache/a.txt")).toBe(true);
    expect(ig.isIgnored("cache")).toBe(false);
  });

  it("anchors patterns that contain a slash to the .gitignore directory", () => {
    const ig = new GitIgnore(new Map([[".gitignore", "/build\nconfig/local.json\n"]]));
    expect(ig.isIgnored("build/out.js")).toBe(true);
    expect(ig.isIgnored("src/build/out.js")).toBe(false);
    expect(ig.isIgnored("config/local.json")).toBe(true);
    expect(ig.isIgnored("x/config/local.json")).toBe(false);
  });

  it("applies a nested .gitignore only below its own directory", () => {
    const ig = new GitIgnore(
      new Map([
        [".gitignore", ""],
        ["apps/web/.gitignore", ".env.local\n"],
      ]),
    );
    expect(ig.isIgnored("apps/web/.env.local")).toBe(true);
    expect(ig.isIgnored("apps/api/.env.local")).toBe(false);
  });

  it("cannot re-include a file whose parent directory is ignored", () => {
    const ig = new GitIgnore(new Map([[".gitignore", "secrets/\n!secrets/keep.txt\n"]]));
    expect(ig.isIgnored("secrets/keep.txt")).toBe(true);
  });

  it("skips comments and blank lines", () => {
    const ig = new GitIgnore(new Map([[".gitignore", "# .env\n\n   \n*.log\n"]]));
    expect(ig.isIgnored(".env")).toBe(false);
    expect(ig.isIgnored("debug.log")).toBe(true);
  });
});

describe("git index", () => {
  it("lists tracked paths from a format 2 index", () => {
    const tracked = parseGitIndex(buildIndex([".env.local", "src/a.ts", "a-much-longer/path/to/some/file.tsx"]));
    expect([...tracked!].sort()).toEqual([".env.local", "a-much-longer/path/to/some/file.tsx", "src/a.ts"]);
  });

  it("returns null for the compressed format 4, bad magic and truncated data", () => {
    expect(parseGitIndex(buildIndex(["a"], 4))).toBeNull();
    const bad = buildIndex(["a"]);
    bad[0] = 0x58;
    expect(parseGitIndex(bad)).toBeNull();
    expect(parseGitIndex(buildIndex(["abc", "def"]).subarray(0, 80))).toBeNull();
    expect(parseGitIndex(new Uint8Array(4))).toBeNull();
  });
});

describe("config", () => {
  it("returns defaults for an empty object", () => {
    expect(parseConfig("{}")).toEqual(DEFAULT_CONFIG);
  });

  it("reads lists and trims entries", () => {
    const c = parseConfig('{"$schema":"x","authHelpers":[" requireOrgMember "],"publicRoutes":["app/api/health/**"],"ignoreRules":["no-rate-limit"]}');
    expect(c.authHelpers).toEqual(["requireOrgMember"]);
    expect(c.publicRoutes).toEqual(["app/api/health/**"]);
    expect(c.ignoreRules).toEqual(["no-rate-limit"]);
  });

  it.each([
    ["not json", "{"],
    ["an array", "[]"],
    ["an unknown key", '{"authHelper":["x"]}'],
    ["a non-array value", '{"authHelpers":"x"}'],
    ["an empty string entry", '{"authHelpers":[""]}'],
    ["an unknown rule id", '{"ignoreRules":["no-such-rule"]}'],
  ])("rejects %s", (_name, text) => {
    expect(() => parseConfig(text)).toThrow(ConfigError);
  });
});

function finding(overrides: Partial<Finding>): Finding {
  return { rule: "api-route-no-auth", severity: "high", file: "a.ts", line: 3, title: "t", message: "m", evidence: "e", fix: "f", ...overrides };
}

describe("suppression comments", () => {
  it("parses the three directive kinds, reasons and rule lists", () => {
    const d = parseDirectives(["// saas-audit-ignore-next-line api-route-no-auth, api-idor -- public by design", "code();", "x(); // saas-audit-ignore-line no-rate-limit", "/* saas-audit-ignore-file all */"].join("\n"));
    expect(d.map((x) => [x.kind, x.rules, x.target])).toEqual([
      ["ignore-next-line", ["api-route-no-auth", "api-idor"], 2],
      ["ignore-line", ["no-rate-limit"], 3],
      ["ignore-file", ["all"], 0],
    ]);
  });

  it("lets stacked next-line directives all point at the code line", () => {
    const d = parseDirectives("// saas-audit-ignore-next-line a-rule\n// saas-audit-ignore-next-line b-rule\ncode();");
    expect(d.map((x) => x.target)).toEqual([3, 3]);
  });

  it("suppresses by line, next line and file, keeps the rest, and reports unused directives", () => {
    const text = ["// saas-audit-ignore-next-line api-route-no-auth", "export async function GET() {}", "", "// saas-audit-ignore-line api-idor", "// saas-audit-ignore-file no-rate-limit"].join("\n");
    const out = applySuppressions(
      [finding({ line: 2 }), finding({ line: 9 }), finding({ rule: "no-rate-limit", line: 40 }), finding({ rule: "api-idor", line: 99 })],
      new Map([["a.ts", text]]),
      new Set(),
    );
    expect(out.suppressed.map((f) => f.line).sort((a, b) => a - b)).toEqual([2, 40]);
    expect(out.kept.map((f) => f.line).sort((a, b) => a - b)).toEqual([9, 99]);
    expect(out.warnings).toEqual(["a.ts:4: saas-audit-ignore-line api-idor suppresses nothing"]);
  });

  it("warns about unknown rule names and directives without rules", () => {
    const out = applySuppressions([], new Map([["a.ts", "// saas-audit-ignore-next-line made-up-rule\n// saas-audit-ignore-file\n"]]), new Set());
    expect(out.warnings).toEqual(['a.ts:1: saas-audit-ignore-next-line names unknown rule "made-up-rule"', "a.ts:2: saas-audit-ignore-file names no rule"]);
  });
});

describe("project collection", () => {
  const dirs: string[] = [];
  const tmp = (): string => {
    const d = mkdtempSync(join(tmpdir(), "saas-audit-"));
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("reads source, SQL, env, .gitignore and package.json; skips build output, dependencies and declarations", () => {
    const root = tmp();
    for (const [path, text] of Object.entries({
      "app/page.tsx": "export default function P() { return null }",
      "supabase/migrations/001.sql": "create table t (id int);",
      ".env.local": "A=1",
      ".gitignore": ".env*",
      "package.json": "{}",
      "node_modules/x/index.js": "x",
      ".next/server/a.js": "x",
      "dist/a.js": "x",
      "types/globals.d.ts": "declare const x: number;",
      "public/logo.png": "binary",
      "README.md": "# hi",
    })) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), text);
    }
    const p = collectProject(root, { ignorePaths: [] });
    expect([...p.files.keys()].sort()).toEqual([".env.local", ".gitignore", "app/page.tsx", "package.json", "supabase/migrations/001.sql"]);
    expect(p.paths.has("public/logo.png")).toBe(true);
    expect(p.paths.has("node_modules/x/index.js")).toBe(false);
    expect(p.gitTracked).toBeNull();
  });

  it("applies ignorePaths to files and directories", () => {
    const root = tmp();
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "app"));
    writeFileSync(join(root, "scripts/seed.ts"), "x");
    writeFileSync(join(root, "app/a.ts"), "x");
    writeFileSync(join(root, "app/a.test.ts"), "x");
    const p = collectProject(root, { ignorePaths: ["scripts", "**/*.test.ts"] });
    expect([...p.files.keys()]).toEqual(["app/a.ts"]);
  });

  it("skips files above the size limit with a warning, and never follows symlinks", () => {
    const root = tmp();
    const outside = tmp();
    writeFileSync(join(outside, "secret.ts"), "export const outside = 1;");
    writeFileSync(join(root, "big.ts"), "a".repeat(DEFAULT_LIMITS.maxFileBytes + 1));
    symlinkSync(outside, join(root, "linked"));
    symlinkSync(join(outside, "secret.ts"), join(root, "linked.ts"));
    const p = collectProject(root, { ignorePaths: [] });
    expect(p.files.size).toBe(0);
    expect(p.skipped).toEqual(["big.ts: not read, larger than 1048576 bytes"]);
  });

  it("reads tracked paths from .git/index when it is present, and warns when it cannot", () => {
    const root = tmp();
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".git/index"), buildIndex([".env.local", "a.ts"]));
    writeFileSync(join(root, "a.ts"), "x");
    expect([...collectProject(root, { ignorePaths: [] }).gitTracked!].sort()).toEqual([".env.local", "a.ts"]);

    writeFileSync(join(root, ".git/index"), buildIndex(["a.ts"], 4));
    const p = collectProject(root, { ignorePaths: [] });
    expect(p.gitTracked).toBeNull();
    expect(p.warnings[0]).toContain("unsupported format");
  });
});
