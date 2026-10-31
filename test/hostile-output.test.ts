import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { projectName } from "../src/report/common.js";
import { renderHuman } from "../src/report/human.js";
import { renderJson } from "../src/report/json.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { escapeControls, mdCode, mdFence, mdText, terminalText } from "../src/report/text.js";
import { scrubSecrets } from "../src/redact.js";
import { shellQuote } from "../src/shell.js";
import { projectFromFiles } from "../src/project.js";
import type { AuditResult } from "../src/types.js";
import { base64url, fakeKey, randomToken, run } from "./helpers.js";

const ESC = "\u001b";
const BEL = "\u0007";
const opts = (name = "demo") => ({ name, version: "1.0.0" });

/** Control characters other than a newline. A terminal or a pager would act on any of them. */
const ACTIVE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;

function hostile(path: string, files: Record<string, string> = {}): AuditResult {
  return run({ [path]: 'export async function GET() { return Response.json(await supabase.from("a").select()); }\n', ...files });
}

describe("terminal output", () => {
  it("never prints an escape sequence from a file name, and shows it visibly instead", () => {
    const r = hostile(`app/api/x${ESC}]8;;https://evil.example${BEL}y${ESC}[2J${ESC}]0;owned${BEL}/route.ts`);
    const text = renderHuman(r, { ...opts(), color: false });
    expect(ACTIVE.test(text)).toBe(false);
    expect(text).toContain("\\x1b]8;;https://evil.example\\x07y\\x1b[2J\\x1b]0;owned\\x07");
  });

  it("neutralises control characters in the evidence line, the title and the warnings", () => {
    const r = run({
      "supabase/migrations/001.sql": `create table public.t (id int);\n-- saas-audit-ignore-next-line ${ESC}[31mfake\n`,
      "app/api/a/route.ts": `export async function GET() { const x = "${ESC}[1A${ESC}[2K No findings."; return Response.json(await supabase.from("a").select()); }\n`,
    });
    const text = renderHuman(r, { ...opts(), color: false });
    expect(ACTIVE.test(text)).toBe(false);
    expect(text).toContain("\\x1b[1A\\x1b[2K No findings.");
    expect(text).toMatch(/warning: .*unknown rule "\\x1b\[31mfake"/);
  });

  it("shows bidirectional overrides and zero-width characters as escapes", () => {
    const r = hostile("app/api/gpj\u202etxt.ts\u200b/route.ts");
    const text = renderHuman(r, { ...opts(), color: false });
    expect(text).not.toMatch(/[\u202a-\u202e\u200b]/);
    expect(text).toContain("gpj\\u{202e}txt.ts\\u{200b}");
  });

  it("keeps a hostile package name on one line in the header", () => {
    const project = projectFromFiles({ "package.json": JSON.stringify({ name: `x${ESC}[2J\n## Injected` }) });
    const name = projectName(project);
    const text = renderHuman(run({}), { ...opts(name), color: false });
    expect(ACTIVE.test(text)).toBe(false);
    expect(text.split("\n")[0]).toBe("saas-audit 1.0.0: x\\x1b[2J\\n## Injected");
  });

  it("only emits its own colour codes, and only when asked", () => {
    const r = hostile("app/api/a/route.ts");
    expect(renderHuman(r, { ...opts(), color: false })).not.toContain(ESC);
    const colored = renderHuman(r, { ...opts(), color: true });
    expect(colored.replace(/\u001b\[[0-9;]*m/g, "")).not.toContain(ESC);
  });

  it("escapes every unsafe character class", () => {
    expect(escapeControls("a\tb\nc\rd")).toBe("a\\tb\\nc\\rd");
    expect(escapeControls("\u0000\u007f\u009b")).toBe("\\x00\\x7f\\x9b");
    expect(escapeControls("\u2028\u2029\ufeff\u061c")).toBe("\\u{2028}\\u{2029}\\u{feff}\\u{61c}");
    expect(escapeControls("\ud800")).toBe("\\u{d800}");
    expect(escapeControls("plain text, ünïcode and 😀")).toBe("plain text, ünïcode and 😀");
    expect(terminalText(`${ESC}[31m`)).toBe("\\x1b[31m");
  });

  it("keeps JSON lossless: the exact text is there, JSON itself escapes the control characters", () => {
    const file = `app/api/x${ESC}]0;t${BEL}/route.ts`;
    const r = hostile(file);
    const json = renderJson(r, opts());
    expect(json).not.toContain(ESC);
    expect(JSON.parse(json).findings[0].file).toBe(file);
  });
});

/** Minimal CommonMark fence tracking: lines outside fenced code blocks. */
function outsideFences(md: string): string[] {
  const out: string[] = [];
  let fence: string | null = null;
  for (const line of md.split("\n")) {
    if (fence === null) {
      const open = /^(`{3,})$/.exec(line);
      if (open) fence = open[1]!;
      else out.push(line);
    } else if (line === fence) fence = null;
  }
  expect(fence).toBeNull();
  return out;
}

/** Number of table cells, counting only unescaped pipes. */
function cells(row: string): number {
  return row.replace(/\\\|/g, "").split("|").length - 2;
}

describe("markdown output", () => {
  it("escapes markup, HTML, links, mentions and math in untrusted text", () => {
    expect(mdText("<img src=//evil/x>")).toBe("\\<img src=//evil/x>");
    expect(mdText("[click](https://evil.example)")).toBe("\\[click\\](https\\://evil.example)");
    expect(mdText("@maintainer www.evil.example $x$")).toBe("\\@maintainer www\\.evil.example \\$x\\$");
    expect(mdText("*bold* `code` a|b &amp;")).toBe("\\*bold\\* \\`code\\` a\\|b \\&amp;");
    expect(mdText("_emph_ snake_case NEXT_PUBLIC_ var")).toBe("\\_emph_ snake_case NEXT_PUBLIC_ var");
    expect(mdText("line one\nline two")).toBe("line one\\nline two");
    expect(mdText("back\\slash")).toBe("back\\\\slash");
  });

  it("chooses code span delimiters longer than any backtick run inside", () => {
    expect(mdCode("a`](https://evil)<img>.ts")).toBe("``a`](https://evil)<img>.ts``");
    expect(mdCode("``x")).toBe("``` ``x ```");
    expect(mdCode("plain")).toBe("`plain`");
    expect(mdCode("a|b", { table: true })).toBe("`a\\|b`");
    expect(mdCode("a\nb")).toBe("`a\\nb`");
  });

  it("chooses a fence longer than any backtick run in the evidence", () => {
    expect(mdFence(["code"])).toEqual(["```", "code", "```"]);
    expect(mdFence(["```", "## Findings", "`````"])).toEqual(["``````", "```", "## Findings", "`````", "``````"]);
  });

  it("cannot be broken out of through a file name, title or evidence line", () => {
    const r = run({
      [`app/api/a\`](https://evil.example)<img src=//evil.example/x>|\n## Forged/route.ts`]: 'export async function GET() { const s = "```"; /*\n*/ return Response.json(await supabase.from("a").select()); }\n',
      "supabase/migrations/001.sql": 'create table public."t`](https://evil)<script>" (id int);\n```\n## No findings\n```\n',
      "package.json": JSON.stringify({ name: "x\n# Heading injected\n<img src=//evil/t>" }),
    });
    const md = renderMarkdown(r, opts(projectName(projectFromFiles({ "package.json": JSON.stringify({ name: "x\n# Heading injected\n<img src=//evil/t>" }) }))));
    const lines = outsideFences(md);
    // no raw HTML, no link syntax, no image anywhere outside code
    for (const line of lines) {
      const prose = line.replace(/(`+).+?\1/g, "");
      expect(prose).not.toMatch(/(?<!\\)<(?:img|script)/);
      expect(prose).not.toMatch(/(?<!\\)\]\(/);
    }
    // headings are exactly the ones the report itself writes
    const headings = lines.filter((l) => /^#{1,6} /.test(l));
    expect(headings[0]).toBe("# Security audit report: x\\n# Heading injected\\n\\<img src=//evil/t>");
    for (const h of headings.slice(1)) expect(h).toMatch(/^(?:## (?:Summary|Findings at a glance|Findings|Findings not counted|Not analysed|Warnings|What was not checked|Rules applied)|### SA-\d{3}: )/);
    expect(lines.filter((l) => l.startsWith("## ")).filter((l) => l.includes("Forged") || l.includes("No findings."))).toEqual([]);
    // every table row keeps its column count
    const glance = lines.slice(lines.indexOf("## Findings at a glance") + 2);
    for (const row of glance.slice(0, glance.indexOf("")).filter((l) => l.startsWith("|"))) expect(cells(row)).toBe(5);
  });

  it("keeps the code span of a location whole when the file name contains backticks, pipes and newlines", () => {
    const r = hostile("app/api/a``b|c\nd/route.ts");
    const md = renderMarkdown(r, opts());
    const row = md.split("\n").find((l) => l.startsWith("| SA-001"))!;
    expect(cells(row)).toBe(5);
    expect(row).toContain("```app/api/a``b\\|c\\nd/route.ts:1```");
    expect(md).toContain("- **Location:** ```app/api/a``b|c\\nd/route.ts:1```");
  });

  it("escapes warnings and skipped entries that quote untrusted text", () => {
    const r = run({}, {});
    const md = renderMarkdown({ ...r, warnings: ["[x](https://evil.example) <b>"], skipped: ["a`b: not read"] }, opts());
    expect(md).toContain("- \\[x\\](https\\://evil.example) \\<b>");
    expect(md).toContain("- a\\`b: not read");
  });
});

describe("shell quoting of suggested commands", () => {
  it("round-trips hostile file names through a real shell", () => {
    for (const name of [".env.$(touch pwned)", ".env.x;rm -rf ~", ".env.a'b", ".env.`id`", ".env.a b\nc", ".env.-rf"]) {
      const out = spawnSync("sh", ["-c", `printf %s ${shellQuote(name)}`], { encoding: "utf8" });
      expect(out.stdout).toBe(name);
    }
  });

  it("puts the quoted path into the git rm hint, after --", () => {
    const hostileName = ".env.$(touch pwned)'x";
    const r = run({ [hostileName]: "A_SECRET=1234\n", ".gitignore": "" }, { tracked: [hostileName] });
    const fix = r.findings.find((f) => f.rule === "secret-committed-env")!.fix;
    expect(fix).toContain("git rm --cached -- '.env.$(touch pwned)'\\''x'");
  });

  it("quotes a hostile dependency name in the pin hint", () => {
    const r = run({ "package.json": JSON.stringify({ name: "x", dependencies: { "a;touch pwned": "latest" } }), "package-lock.json": "{}" });
    expect(r.findings.find((f) => f.rule === "deps-unpinned")!.fix).toContain("npm install 'a;touch pwned@<version>' --save-exact");
  });
});

describe("secrets in evidence", () => {
  const body = randomToken(64, 21);

  it("never prints the body of a private key written as a one-line literal", () => {
    const header = fakeKey("-----BEGIN ", "PRIV", "ATE KEY-----");
    const footer = fakeKey("-----END ", "PRIV", "ATE KEY-----");
    const r = run({ "lib/k.ts": `export const key = "${header}\\n${body}\\n${footer}";\n` });
    const f = r.findings.find((x) => x.rule === "secret-hardcoded")!;
    expect(f.evidence).toBe("key = [private key block, 118 chars]");
    expect(JSON.stringify(r)).not.toContain(body.slice(0, 16));
  });

  it("does not print a secret written with escape sequences", () => {
    const token = randomToken(28, 22);
    const r = run({ "lib/k.ts": `export const key = "\\x73k_live_${token}";\n` });
    const f = r.findings.find((x) => x.rule === "secret-hardcoded")!;
    expect(f.severity).toBe("critical");
    expect(JSON.stringify(r)).not.toContain(token.slice(0, 12));
  });

  it("withholds a line that another rule reports when the secret on it is escaped", () => {
    const token = randomToken(28, 23);
    const r = run({ "lib/k.ts": `export const a = "\\x73k_live_${token}", b = process.env.NEXT_PUBLIC_API_SECRET;\n` });
    const f = r.findings.find((x) => x.rule === "secret-in-client")!;
    expect(f.evidence).toBe("[line withheld: it contains an escaped secret]");
    expect(JSON.stringify(r)).not.toContain(token.slice(0, 12));
  });

  it("scrubs a plain secret from the evidence of any other rule", () => {
    const token = randomToken(28, 24);
    const key = fakeKey("sk", "_live_", token);
    const r = run({ "lib/k.ts": `export const a = process.env.NEXT_PUBLIC_API_SECRET, b = "${key}";\n` });
    const f = r.findings.find((x) => x.rule === "secret-in-client")!;
    expect(f.evidence).toContain("sk_l…[36 chars]");
    expect(JSON.stringify(r)).not.toContain(token.slice(0, 12));
  });

  it("scrubs before truncating, so a secret straddling the cut is not half printed", () => {
    const token = randomToken(30, 25);
    const key = fakeKey("sk", "_live_", token);
    const pad = " ".repeat(100);
    const line = `export const a = process.env.NEXT_PUBLIC_API_SECRET;${pad}export const b = "${key}";`;
    expect(line.indexOf(key)).toBeLessThan(180);
    expect(line.indexOf(key) + key.length).toBeGreaterThan(180);
    const r = run({ "lib/k.ts": `${line}\n` });
    const f = r.findings.find((x) => x.rule === "secret-in-client")!;
    expect(f.evidence.length).toBeLessThanOrEqual(180);
    expect(f.evidence).not.toContain(token.slice(0, 8));
    expect(f.evidence).not.toContain("sk_live_");
  });

  it("does not let a database password that looks like a replacement pattern expand into the line", () => {
    const url = "postgres://app:$'abcdefgh1234@db.example.test:5432/app";
    expect(scrubSecrets(`const url = "${url}"; const keep = 1;`)).toBe('const url = "postgres://app:[password withheld]@db.example.test:5432/app"; const keep = 1;');
    const r = run({ "lib/db.ts": `export const url = "${url}"; export const keep = process.env.NEXT_PUBLIC_API_SECRET;\n` });
    expect(JSON.stringify(r)).not.toContain("abcdefgh1234");
  });

  it("scrubs JWTs and leaves ordinary text alone", () => {
    const jwt = `${base64url({ alg: "HS256" })}.${base64url({ role: "anon" })}.${randomToken(43, 26)}`;
    expect(scrubSecrets(`token: ${jwt};`)).toBe("token: [JWT withheld];");
    const ordinary = 'export const label = "nothing secret here"; // sk-learn is a library';
    expect(scrubSecrets(ordinary)).toBe(ordinary);
  });
});
