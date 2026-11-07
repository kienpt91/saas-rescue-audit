import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { RULES } from "../src/catalog.js";
import { run as runCli, type Io } from "../src/cli.js";
import { DEFAULT_CONFIG, parseConfig } from "../src/config.js";
import { collectProject, projectFromFiles } from "../src/project.js";
import { renderJson } from "../src/report/json.js";
import { encodePath, encodeSegment, exportFindings, isRepositoryPath, MAX_BYTES, MAX_RECORDS, omissionLines, type FindingRecord } from "../src/report/findings.js";
import { FALLBACK_PLAN, RULE_PLANS, STATIC_ONLY_BLOCKER } from "../src/report/findings-plans.js";
import type { AuditResult, Finding, Project } from "../src/types.js";
import { conformanceErrors, conformanceErrorsOfText, isSafePath } from "./findings-conformance.js";
import { fakeKey, run } from "./helpers.js";

const example = (name: string): string => fileURLToPath(new URL(`../examples/${name}`, import.meta.url));

function auditDir(root: string): { result: AuditResult; project: Project } {
  let config = parseConfig("{}");
  try {
    config = parseConfig(readFileSync(`${root}/saas-audit.config.json`, "utf8"));
  } catch {
    // the flawed app has no config
  }
  const project = collectProject(root, config);
  return { result: audit(project, config), project };
}

function lineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

const TICKETS_SQL = [
  "create table public.tickets (id uuid primary key, user_id uuid references auth.users(id));",
  "alter table public.tickets enable row level security;",
  'create policy "Anyone can use tickets" on public.tickets for all using (true) with check (true);',
  "",
].join("\n");

const WEBHOOK_ROUTE = [
  "// stripe webhook",
  "export async function POST(req: Request) {",
  "  const body = await req.json();",
  '  if (body.type === "checkout.session.completed") {',
  '    await supabase.from("orders").update({ paid: true }).eq("id", body.data.object.id);',
  "  }",
  '  return new Response("ok");',
  "}",
  "",
].join("\n");

const OPEN_ROUTE = 'export async function GET() {\n  const { data } = await supabase.from("notes").select("*");\n  return Response.json(data);\n}\n';

// ---------------------------------------------------------------------------------------------
// seeded generator of odd projects

function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ODD_PIECES = ["a", "B", "7", " ", '"', "'", ":", "/", "\\", "\n", "\u001b", "\u202e", "\u200b", "\ud800", "\udc00", "é", "日本", "😀", "\u0000", "`", "$", "@", "+", "%", "..", ".", "-", "_", "\u2028", "\ufeff"];

function oddName(next: () => number, max = 5): string {
  const n = 1 + Math.floor(next() * max);
  let out = "";
  for (let i = 0; i < n; i++) out += ODD_PIECES[Math.floor(next() * ODD_PIECES.length)] ?? "x";
  return out;
}

const pick = <T>(next: () => number, list: readonly T[]): T => list[Math.floor(next() * list.length)]!;
const sqlName = (name: string): string => `"${name.replace(/"/g, '""')}"`;

function randomProject(seed: number): Record<string, string> {
  const next = prng(seed);
  const files: Record<string, string> = {};
  const count = 2 + Math.floor(next() * 5);
  for (let i = 0; i < count; i++) {
    const kind = pick(next, ["sql", "route", "action", "env", "package", "next-config", "webhook", "client"] as const);
    const weird = next() < 0.4;
    const seg = weird ? oddName(next) : `part${i}`;
    if (kind === "sql") {
      const table = weird ? oddName(next) : `t${i}`;
      const policy = oddName(next, 4);
      const command = pick(next, ["all", "select", "insert", "update", "delete"]);
      const role = pick(next, ["anon", "authenticated", "public"]);
      const using = pick(next, ["true", "1 = 1", "auth.uid() = user_id", "((((true))))"]);
      const rls = next() < 0.7 ? `alter table public.${sqlName(table)} enable row level security;\n` : "";
      const pol = next() < 0.8 ? `create policy ${sqlName(policy)} on public.${sqlName(table)} for ${command} to ${role} using (${using});\n` : "";
      files[`supabase/migrations/${seg}${i}.sql`] = `create table public.${sqlName(table)} (id int, user_id uuid);\n${rls}${pol}`;
    } else if (kind === "route" || kind === "webhook") {
      const verb = pick(next, ["GET", "POST", "PUT", "DELETE"]);
      const table = oddName(next, 3).replace(/["\\\n\r]/g, "");
      const body =
        kind === "webhook"
          ? `// stripe webhook\nexport async function ${verb}(req: Request) {\n  const body = await req.json();\n  await supabase.from("orders").update({ paid: true }).eq("id", body.id);\n  return Response.json({});\n}\n`
          : `export async function ${verb}(req: Request) {\n  const id = new URL(req.url).searchParams.get("id");\n  const { data } = await supabase.from("${table}").select("*").eq("id", id);\n  return Response.json(data);\n}\n`;
      files[`app/api/${kind === "webhook" ? "stripe/webhook" : seg}/route.ts`] = body;
    } else if (kind === "action") {
      files[`app/${seg}/actions.ts`] = `"use server";\nexport async function save${i}(form: FormData) {\n  await db.insert(notes).values({ userId: form.get("userId"), text: form.get("t") });\n}\n`;
    } else if (kind === "env") {
      files[`${pick(next, ["", "app/", "a:b/"])}.env${pick(next, [".local", ".production", ""])}`] = `NEXT_PUBLIC_${pick(next, ["SECRET_KEY", "SERVICE_ROLE", "PRIVATE_TOKEN"])}=x\n# ${oddName(next)}\n`;
    } else if (kind === "package") {
      files["package.json"] = `{\n  "name": ${JSON.stringify(oddName(next))},\n  "dependencies": { "next": "latest", ${JSON.stringify(oddName(next))}: "*" }\n}\n`;
    } else if (kind === "next-config") {
      files["next.config.mjs"] = `const cfg = {\n  typescript: { ignoreBuildErrors: true },\n};\nexport default cfg;\n`;
    } else {
      files[`components/${seg}.tsx`] = `"use client";\nexport function C(p: { h: string }) {\n  const k = process.env.SECRET_TOKEN;\n  return <div dangerouslySetInnerHTML={{ __html: p.h }} data-k={k} />;\n}\n`;
    }
  }
  return files;
}

function exportFiles(files: Record<string, string>) {
  return exportFindings(run(files));
}

const shifted = (files: Record<string, string>, lines: number): Record<string, string> => Object.fromEntries(Object.entries(files).map(([path, text]) => [path, "\n".repeat(lines) + text]));

// ---------------------------------------------------------------------------------------------

type Step = string | number;
const REMOVE = Symbol("remove");

function child(node: unknown, step: Step): unknown {
  if (typeof node !== "object" || node === null) throw new Error(`no ${String(step)} in a non-object`);
  return Reflect.get(node, step);
}

/** The records of an export as plain loose objects, for tests that read fields without trusting a shape. */
function looseRecords(text: string): Record<string, unknown>[] {
  const doc: unknown = JSON.parse(text);
  if (!Array.isArray(doc)) throw new Error("not an array");
  return doc.map((item: unknown) => {
    if (typeof item !== "object" || item === null) throw new Error("not an object");
    return Object.fromEntries(Object.entries(item));
  });
}

describe("conformance check (the test oracle)", () => {
  const base = exportFiles({ "supabase/migrations/001.sql": "create table public.notes (id int);\n" }).records[0]!;

  /** Conformance errors of a document with one record, after setting (or removing) one value inside it. */
  function mutated(path: readonly Step[], value: unknown): string[] {
    const doc: unknown = JSON.parse(JSON.stringify([base]));
    let parent: unknown = child(doc, 0);
    for (const step of path.slice(0, -1)) parent = child(parent, step);
    if (typeof parent !== "object" || parent === null) throw new Error("bad path");
    const last = path[path.length - 1]!;
    if (value === REMOVE) Reflect.deleteProperty(parent, last);
    else Reflect.set(parent, last, value);
    return conformanceErrors(doc);
  }

  it("accepts a real record", () => {
    expect(conformanceErrors([base])).toEqual([]);
  });

  it.each<[string, Step[], unknown]>([
    ["a confirmed verdict", ["verdict"], "confirmed"],
    ["an unknown verdict", ["verdict"], "maybe"],
    ["an extra property", ["severity"], "high"],
    ["a missing description", ["description"], REMOVE],
    ["an empty title", ["title"], ""],
    ["a whitespace title", ["title"], " \t "],
    ["an invisible-only title", ["title"], "\u200b\u2060"],
    ["a lone surrogate", ["title"], "bad \ud800 text"],
    ["a fingerprint with a space", ["fingerprint"], "a b"],
    ["a fingerprint starting with a symbol", ["fingerprint"], "-abc"],
    ["an empty trace", ["trace"], []],
    ["a trace line of 0", ["trace", 0, "line"], 0],
    ["a fractional trace line", ["trace", 0, "line"], 1.5],
    ["a trace kind of propagation alone", ["trace", 0, "kind"], "propagation"],
    ["an absolute path", ["evidence", 0, "file"], "/etc/passwd"],
    ["a parent path", ["evidence", 0, "file"], "a/../b"],
    ["a backslash path", ["evidence", 0, "file"], "a\\b"],
    ["a colon path", ["evidence", 0, "file"], "a:b"],
    ["a trailing dot", ["evidence", 0, "file"], "dir./x"],
    ["a reserved name", ["evidence", 0, "file"], "src/con.ts"],
    ["a severity on needs_validation", ["severity"], {}],
    ["no blockers", ["blockers"], []],
    ["duplicate blockers", ["blockers"], ["x", "x"]],
    ["an empty validation plan", ["validation_plan"], {}],
    ["an unknown plan key", ["validation_plan"], { local: "x", remote: "y" }],
    ["a reason on needs_validation", ["reason"], "x"],
  ])("rejects %s", (_name, path, value) => {
    expect(mutated(path, value).length).toBeGreaterThan(0);
  });

  it("rejects duplicate trace items, a wrong trace order, duplicate and unsorted fingerprints", () => {
    const step = base.trace[0]!;
    expect(mutated(["trace"], [{ ...step, kind: "entrypoint" }, { ...step, kind: "entrypoint" }])).not.toEqual([]);
    expect(mutated(["trace"], [{ ...step, kind: "sink" }, { ...step, kind: "entrypoint" }]).join("\n")).toContain("must start with an entrypoint");
    const a = structuredClone(base);
    const b = structuredClone(base);
    expect(conformanceErrors([a, b]).join("\n")).toContain("duplicate");
    b.fingerprint = "A";
    a.fingerprint = "b";
    expect(conformanceErrors([a, b]).join("\n")).toContain("sorted");
  });

  it("rejects a document that is not an array, and over-long ones", () => {
    expect(conformanceErrors({})).not.toEqual([]);
    expect(conformanceErrorsOfText("not json")).toEqual(["$: not valid JSON"]);
    expect(conformanceErrorsOfText("x".repeat(MAX_BYTES + 1))[0]).toContain("exceed");
  });

  it("agrees with the encoder's path rule on a table of paths", () => {
    const paths = ["a/b.ts", ".env.local", "[id]/route.ts", "a b/c", "a/", "/a", "a//b", "a:b", "a\\b", "a./b", "a /b", "con", "nul.txt", "com1", "x\u0000y", "x\u202ey", "x\ud800", "~a", ".", "..", "a/./b", " a", "日本/ファイル.ts", "a/b.c.d"];
    for (const p of paths) expect(isRepositoryPath(p), JSON.stringify(p)).toBe(isSafePath(p));
  });

  // Facts of the format written out literally, so the encoder and the oracle cannot drift together: true = accepted.
  it.each<[string, boolean]>([
    ["com0", true],
    ["lpt0.txt", true],
    ["src/com0/x.ts", true],
    ["com1", false],
    ["COM9.log", false],
    ["com\u00b9", false],
    ["lpt\u00b2.txt", false],
    ["a/LPT\u00b3", false],
    ["lpt9.x", false],
    ["com10", true],
    ["comx", true],
    ["CON.txt", false],
    ["prn", false],
    ["Aux.tar.gz", false],
    ["conin$", false],
    ["CLOCK$.js", false],
    ["a/nul.", false],
    ["a/nul /b", false],
    ["console.ts", true],
    ["C:", false],
    ["C:/x", false],
    ["~", false],
    ["~x/y", false],
    ["x/~", true],
    ["a/b ", false],
    ["a\u00a0", false],
    ["a\u00ad/b", false],
    ["a\u2028b", false],
  ])("agrees with the format on the path %j: accepted=%s", (path, accepted) => {
    expect(isRepositoryPath(path)).toBe(accepted);
    expect(isSafePath(path)).toBe(accepted);
  });
});

describe("fingerprint encoding", () => {
  it("keeps letters, digits, dot, underscore and dash and writes every other byte as +xx", () => {
    expect(encodeSegment("Anyone can use tickets")).toBe("Anyone+20can+20use+20tickets");
    expect(encodeSegment("a:b+c/d")).toBe("a+3ab+2bc+2fd");
    expect(encodeSegment("é")).toBe("+c3+a9");
    expect(encodeSegment("x_y-z.1")).toBe("x_y-z.1");
    expect(encodeSegment("\ud800")).toBe("+ef+bf+bd");
    expect(encodePath("supabase/migrations/a b.sql")).toBe("supabase/migrations/a+20b.sql");
  });

  it("is the one proof-audit builds for a Supabase policy finding", () => {
    const { records } = exportFiles({ "supabase/migrations/20260105090000_init.sql": TICKETS_SQL });
    expect(records.map((r) => r.fingerprint)).toEqual([
      "saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:public.tickets:Anyone+20can+20use+20tickets",
      "saas-audit/supabase-tenant-unscoped:supabase/migrations/20260105090000_init.sql:public.tickets",
    ]);
  });

  it("publishes the identity in --json as subject, so a policy name never has to be parsed out of a title", () => {
    const result = run({ "supabase/migrations/20260105090000_init.sql": TICKETS_SQL.replace("Anyone can use tickets", 'say ""hi"" now') });
    const policy = result.findings.find((f) => f.rule === "supabase-policy-permissive")!;
    expect(policy.subject).toEqual(["public.tickets", 'say "hi" now']);
    expect(policy.entry).toMatchObject({ file: "supabase/migrations/20260105090000_init.sql", line: 1 });
    const json = renderJson(result, { name: "x", version: "0" });
    expect(json).toContain('"subject": [');
    expect(exportFindings(result).records.map((r) => r.fingerprint)[0]).toBe("saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:public.tickets:say+20+22hi+22+20now");
  });

  it("separates findings that share an identity by their order, with an @ suffix no encoded name can contain", () => {
    const files = { "components/A.tsx": '"use client";\nexport const A = (p: { h: string }) => <div dangerouslySetInnerHTML={{ __html: p.h }} />;\nexport const B = (p: { h: string }) => <div dangerouslySetInnerHTML={{ __html: p.h }} />;\n' };
    const fps = exportFiles(files).records.map((r) => r.fingerprint);
    expect(fps).toHaveLength(2);
    expect(fps[1]).toBe(`${fps[0]}@2`);
    expect(fps[0]).not.toContain("@");
  });
});

describe("the vibe-app example", () => {
  const { result, project } = auditDir(example("vibe-app"));
  const exported = exportFindings(result);

  it("exports every finding as needs_validation and nothing else", () => {
    expect(exported.omitted).toEqual([]);
    expect(exported.records).toHaveLength(result.findings.length);
    expect(exported.records.every((r) => r.verdict === "needs_validation")).toBe(true);
    expect(conformanceErrorsOfText(exported.text)).toEqual([]);
  });

  it("never carries a severity or a confirmed verdict, and starts every list of blockers with the static-only limit", () => {
    for (const r of exported.records) {
      expect(r).not.toHaveProperty("severity");
      expect(r.verdict).not.toBe("confirmed");
      if (r.verdict === "needs_validation") {
        expect(r.blockers[0]).toBe(STATIC_ONLY_BLOCKER);
        expect(r.validation_plan.local.length).toBeGreaterThan(20);
      }
    }
  });

  it("points every trace step and evidence item at a line that exists, and quotes that line", () => {
    for (const r of exported.records) {
      for (const site of [...r.trace, ...r.evidence]) {
        const text = project.files.get(site.file);
        expect(text, `${r.fingerprint} -> ${site.file}`).toBeDefined();
        expect(site.line).toBeGreaterThanOrEqual(1);
        expect(site.line).toBeLessThanOrEqual(lineCount(text!));
      }
      for (const item of r.evidence) {
        const body = item.description.replace(/^Source line: /, "");
        if (body.includes("…") || body.includes("[") || body === "(blank line)") continue;
        expect(project.files.get(item.file)!.split(/\r?\n/)[item.line - 1]!.trim(), r.fingerprint).toBe(body);
      }
    }
  });

  it("ends every trace at the evidence it quotes first, and starts it at the handler where the rule knows one", () => {
    for (const r of exported.records) {
      const sink = r.trace[r.trace.length - 1]!;
      expect(`${r.evidence[0]!.file}:${r.evidence[0]!.line}`).toBe(`${sink.file}:${sink.line}`);
    }
    const noAuth = exported.records.find((r) => r.fingerprint.startsWith("saas-audit/api-route-no-auth:app/api/projects/route.ts:POST+20handler"));
    expect(noAuth?.trace.map((t) => t.kind)).toEqual(["entrypoint", "sink"]);
    expect(project.files.get(noAuth!.trace[0]!.file)!.split("\n")[noAuth!.trace[0]!.line - 1]).toMatch(/export async function POST/);
    const policy = exported.records.find((r) => r.fingerprint.startsWith("saas-audit/supabase-policy-permissive:"));
    expect(policy?.trace.map((t) => t.kind)).toEqual(["entrypoint", "sink"]);
    expect(policy?.trace[0]?.file).toBe("supabase/migrations/0001_init.sql");
  });

  it("finds a real line for the findings that used to point at line 1", () => {
    const lock = exported.records.find((r) => r.fingerprint.includes("deps-unpinned:package.json:no+20lockfile"))!;
    expect(lock.trace[0]!.line).toBeGreaterThan(1);
    expect(project.files.get("package.json")!.split("\n")[lock.trace[0]!.line - 1]).toMatch(/"(?:dependencies|devDependencies)"/);
    const headers = exported.records.find((r) => r.fingerprint.includes("security-headers:next.config.mjs"))!;
    expect(headers.trace[0]!.line).toBeGreaterThan(1);
    expect(project.files.get("next.config.mjs")!.split("\n")[headers.trace[0]!.line - 1]).toMatch(/nextConfig/);
  });

  it("is identical on a second run and after lines are added above the code", () => {
    expect(exportFindings(auditDir(example("vibe-app")).result).text).toBe(exported.text);
    const files = Object.fromEntries(project.files);
    const original = exportFindings(audit(projectFromFiles(files), DEFAULT_CONFIG));
    const moved = exportFindings(audit(projectFromFiles(shifted(files, 7)), DEFAULT_CONFIG));
    expect(moved.records.map((r) => r.fingerprint)).toEqual(original.records.map((r) => r.fingerprint));
    expect(moved.text).not.toBe(original.text);
    original.records.forEach((r, i) => {
      const m = moved.records[i]!;
      expect(m.trace.map((t) => t.line)).toEqual(r.trace.map((t) => t.line + 7));
      expect(m.evidence.map((e) => e.line)).toEqual(r.evidence.map((e) => e.line + 7));
    });
  });

  it("never repeats a secret value", () => {
    expect(exported.text).not.toContain("replace-with-service-role-key");
    expect(exported.text).not.toContain("replace-with-stripe-secret-key");
  });

  it("is what examples/sample-findings.json holds, which `npm run sample:findings` regenerates", () => {
    expect(readFileSync(example("sample-findings.json"), "utf8")).toBe(exported.text);
  });
});

describe("the vibe-app-fixed example: silenced findings are rejected, with their fingerprints", () => {
  const { result } = auditDir(example("vibe-app-fixed"));
  const exported = exportFindings(result);

  it("exports the three silenced findings as rejected and conforms", () => {
    expect(result.findings).toEqual([]);
    expect(exported.records.map((r) => r.verdict)).toEqual(["rejected", "rejected", "rejected"]);
    expect(conformanceErrorsOfText(exported.text)).toEqual([]);
    for (const r of exported.records) {
      expect(r).not.toHaveProperty("blockers");
      expect(r).toHaveProperty("reason");
    }
  });

  it("says whose decision it was and that nothing was disproved", () => {
    const reasons = exported.records.map((r) => (r.verdict === "rejected" ? r.reason : ""));
    expect(reasons.some((t) => t.includes("saas-audit-ignore comment"))).toBe(true);
    expect(reasons.some((t) => t.includes("ignoreRules"))).toBe(true);
    for (const t of reasons) expect(t).toContain("did not test or disprove");
  });
});

describe("states of one finding keep one fingerprint", () => {
  it("a policy finding keeps its fingerprint when an ignore comment turns it into a rejected record", () => {
    const sql = 'create table public.plans (id int);\nalter table public.plans enable row level security;\ncreate policy "plans are public" on public.plans for select to anon using (true);\n';
    const before = exportFiles({ "supabase/migrations/001.sql": sql });
    const commented = "-- saas-audit-ignore-next-line supabase-policy-permissive -- price list\n" + sql.split("\n").slice(0, 2).join("\n") + "\n" + sql.split("\n")[2]! + "\n";
    const withComment = sql.split("\n");
    withComment.splice(2, 0, "-- saas-audit-ignore-next-line supabase-policy-permissive -- price list");
    const after = exportFiles({ "supabase/migrations/001.sql": withComment.join("\n") });
    expect(commented).toContain("saas-audit-ignore");
    expect(before.records.map((r) => r.verdict)).toEqual(["needs_validation"]);
    expect(after.records.map((r) => r.verdict)).toEqual(["rejected"]);
    expect(after.records[0]!.fingerprint).toBe(before.records[0]!.fingerprint);
    expect(conformanceErrorsOfText(after.text)).toEqual([]);
  });

  it("a route finding keeps its fingerprint when the handler moves down the file", () => {
    const a = exportFiles({ "app/api/notes/route.ts": OPEN_ROUTE });
    const b = exportFiles({ "app/api/notes/route.ts": "// header\n// more\nimport x from 'y';\n\n" + OPEN_ROUTE });
    expect(a.records.map((r) => r.fingerprint)).toEqual(b.records.map((r) => r.fingerprint));
    expect(a.records[0]!.trace[0]!.line).not.toBe(b.records[0]!.trace[0]!.line);
  });

  it("a webhook finding exports the handler as entrypoint and the unverified use as sink", () => {
    const { records } = exportFiles({ "app/api/stripe/webhook/route.ts": WEBHOOK_ROUTE });
    const unverified = records.find((r) => r.fingerprint.startsWith("saas-audit/stripe-webhook-unverified:"))!;
    expect(unverified.trace.map((t) => [t.kind, t.line])).toEqual([
      ["entrypoint", 2],
      ["sink", 3],
    ]);
    if (unverified.verdict !== "needs_validation") throw new Error("expected needs_validation");
    expect(unverified.validation_plan.local).toContain("forged signature");
    expect(unverified.validation_plan.deployment).toBeDefined();
    expect(conformanceErrors(records)).toEqual([]);
  });
});

describe("every rule has a plan", () => {
  it("covers the catalog exactly", () => {
    expect(Object.keys(RULE_PLANS).sort()).toEqual(RULES.map((r) => r.id).sort());
  });

  it("is documented: docs/findings-export.md carries every rule's claim, blockers and validation plans verbatim", () => {
    const doc = readFileSync(fileURLToPath(new URL("../docs/findings-export.md", import.meta.url)), "utf8");
    for (const r of RULES) {
      const plan = RULE_PLANS[r.id]!;
      expect(doc, r.id).toContain(`\`${r.id}\``);
      expect(doc, `${r.id} claim`).toContain(plan.claim);
      expect(doc, `${r.id} local`).toContain(plan.local);
      for (const blocker of plan.blockers) expect(doc, `${r.id} blocker`).toContain(blocker);
      if (plan.deployment) expect(doc, `${r.id} deployment`).toContain(plan.deployment);
    }
  });

  it("has a local plan, a claim and a sink note for every rule, and names the RLS validation tool", () => {
    for (const [id, plan] of Object.entries({ ...RULE_PLANS, fallback: FALLBACK_PLAN })) {
      expect(plan.claim.length, id).toBeGreaterThan(20);
      expect(plan.local.length, id).toBeGreaterThan(20);
      expect(plan.sink.length, id).toBeGreaterThan(5);
      expect(plan.blockers.length, id).toBeGreaterThan(0);
    }
    for (const id of ["supabase-rls-missing", "supabase-policy-permissive", "supabase-policy-missing", "supabase-tenant-unscoped"]) expect(RULE_PLANS[id]!.local).toContain("proof-audit");
  });

  it("produces a conforming record for every rule on a project that triggers it", () => {
    const secret = fakeKey("sk", "_live_", "abcdefghijklmnopqrstuvwx");
    const files: Record<string, string> = {
      "supabase/migrations/001.sql": TICKETS_SQL + "create table public.open (id int);\ncreate table public.closed (id int);\nalter table public.closed enable row level security;\n",
      "app/api/stripe/webhook/route.ts": WEBHOOK_ROUTE,
      "app/api/notes/route.ts": OPEN_ROUTE,
      "app/api/notes/[id]/route.ts": 'export async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data } = await supabase.from("notes").select("*").eq("id", params.id);\n  return Response.json(data);\n}\n',
      "app/api/login/route.ts": 'import { redirect } from "next/navigation";\nexport async function POST(req: Request) {\n  const next = new URL(req.url).searchParams.get("next");\n  redirect(next);\n}\n',
      "components/C.tsx": '"use client";\nexport const C = (p: { h: string }) => <div dangerouslySetInnerHTML={{ __html: p.h }} data-k={process.env.SECRET_TOKEN} />;\n',
      "lib/key.ts": `export const KEY = "${secret}";\n`,
      ".env": "NEXT_PUBLIC_SECRET_KEY=abc\n",
      "package.json": '{ "name": "x", "dependencies": { "next": "latest" } }\n',
      "next.config.mjs": "export default { typescript: { ignoreBuildErrors: true } };\n",
    };
    const result = run(files);
    const exported = exportFindings(result);
    expect(conformanceErrorsOfText(exported.text)).toEqual([]);
    expect(exported.records).toHaveLength(result.findings.length);
    const rules = new Set(result.findings.map((f) => f.rule));
    expect(rules.size).toBeGreaterThanOrEqual(15);
    expect(exported.text).not.toContain(secret);
    for (const r of exported.records) expect(r.claimed_root_cause).not.toBe(FALLBACK_PLAN.claim);
  });
});

describe("odd and hostile input never produces an invalid export", () => {
  const baseResult = run({});
  const finding = (over: Partial<Finding> = {}): Finding => ({
    rule: "api-route-no-auth",
    severity: "high",
    file: "app/api/x/route.ts",
    line: 3,
    title: "A title",
    message: "A message.",
    evidence: "some code",
    fix: "A fix.",
    ...over,
  });
  const exportOf = (findings: Finding[], suppressed: AuditResult["suppressed"] = []) => exportFindings({ ...baseResult, findings, suppressed });

  it("falls back to fixed text for a rule it does not know, an empty title or an invisible-only message", () => {
    const e = exportOf([finding({ rule: "not-a-rule", title: "\u200b\u2060", message: " \u202e ", evidence: "", fix: "\u0000" })]);
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
    expect(e.records[0]!.claimed_root_cause).toBe(FALLBACK_PLAN.claim);
    expect(e.records[0]!.title).toBe("\\u{200b}\\u{2060}");
    expect(e.records[0]!.evidence[0]!.description).toBe("Source line: (blank line)");
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("leaves out a finding whose line is %s, and says so", (line) => {
    const e = exportOf([finding({ line }), finding({ rule: "open-redirect", file: "ok.ts", line: 2 })]);
    expect(e.records).toHaveLength(1);
    expect(e.omitted).toEqual([{ reason: "line-unknown", count: 1 }]);
    expect(omissionLines(e.omitted)[0]).toContain("1 finding left out");
  });

  it.each(["", "/abs", "a:b", "a\\b", "x/../y", "trailing.", "dir /x", "con.ts", "a\u0000b", "a\u202eb", "a\ud800b", "a//b"])("leaves out a finding whose file is %j", (file) => {
    const e = exportOf([finding({ file })]);
    expect(e.records).toEqual([]);
    expect(e.omitted).toEqual([{ reason: "path-not-representable", count: 1 }]);
  });

  it("drops an unusable entry or sink site and keeps the finding", () => {
    const e = exportOf([finding({ entry: { file: "a:b", line: 1, note: "n" }, sink: { file: "ok.ts", line: 0, note: "n" } })]);
    expect(e.records).toHaveLength(1);
    expect(e.records[0]!.trace).toHaveLength(1);
    expect(e.records[0]!.trace[0]!.file).toBe("app/api/x/route.ts");
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
  });

  it("escapes control, bidirectional, zero-width and lone-surrogate characters in every text field", () => {
    const nasty = "a\u001b[31mb\u202ec\u200bd\ud800e\u2028f";
    const e = exportOf([finding({ title: `T ${nasty}`, message: `M ${nasty}`, evidence: `E ${nasty}\nsecond ${nasty}`, subject: [nasty], fix: `F ${nasty}` })]);
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
    const parsed = looseRecords(e.text);
    expect(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\ud800-\udfff]/u.test(JSON.stringify(parsed, null, 1).replace(/\\n/g, ""))).toBe(false);
    expect(e.text).toContain("\\\\x1b");
    expect(e.text).toContain("\\\\u{202e}");
  });

  it("handles a subject that is empty, blank or very long, and an unknown severity", () => {
    const severity = "bogus" as unknown as Finding["severity"]; // a hand-built finding from outside the type system
    const e = exportOf([finding({ subject: [] }), finding({ subject: ["", ""], line: 4 }), finding({ subject: ["x".repeat(50_000)], line: 5, severity })]);
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
    expect(new Set(e.records.map((r) => r.fingerprint)).size).toBe(3);
  });

  it("keeps the highest-rated findings when there are more records than the format allows", () => {
    const many: Finding[] = [];
    for (let i = 0; i < 1200; i++) many.push(finding({ file: `f${i}.ts`, severity: i < 100 ? "critical" : "info" }));
    const e = exportOf(many);
    expect(e.records).toHaveLength(MAX_RECORDS);
    expect(e.omitted).toEqual([{ reason: "record-limit", count: 200 }]);
    expect(e.records.filter((r) => r.description.includes("rates this critical"))).toHaveLength(100);
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
  });

  it("keeps an export under the size limit by leaving out the lowest-rated findings", () => {
    const big: Finding[] = [];
    for (let i = 0; i < 700; i++) big.push(finding({ file: `f${i}.ts`, severity: i < 50 ? "critical" : "low", message: "m".repeat(12_000) }));
    const e = exportOf(big);
    expect(Buffer.byteLength(e.text)).toBeLessThanOrEqual(MAX_BYTES);
    expect(e.omitted.map((o) => o.reason)).toEqual(["size-limit"]);
    expect(e.records.filter((r) => r.description.includes("rates this critical"))).toHaveLength(50);
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
  });

  it("treats a silenced finding with an odd reason as rejected with that reason in plain text", () => {
    const e = exportOf([], [{ ...finding(), suppressedBy: "weird\u001b setting" }]);
    const record = e.records[0]!;
    if (record.verdict !== "rejected") throw new Error("expected rejected");
    expect(record.reason).toContain("weird\\x1b setting");
    expect(conformanceErrorsOfText(e.text)).toEqual([]);
  });

  it("exports an empty array for a clean project", () => {
    expect(exportOf([]).text).toBe("[]\n");
  });
});

describe("property: any generated project exports a conforming, stable array", () => {
  const SEEDS = Array.from({ length: 300 }, (_, i) => i + 1);

  it("conforms, and parses back to the same records", () => {
    let records = 0;
    let omitted = 0;
    for (const seed of SEEDS) {
      const files = randomProject(seed);
      const exported = exportFiles(files);
      const errors = conformanceErrorsOfText(exported.text);
      expect(errors, `seed ${seed}`).toEqual([]);
      expect(JSON.parse(exported.text), `seed ${seed}`).toEqual(exported.records);
      records += exported.records.length;
      omitted += exported.omitted.reduce((n, o) => n + o.count, 0);
    }
    expect(records).toBeGreaterThan(300);
    expect(omitted).toBeGreaterThan(0);
  });

  it("gives the same text twice, and the same fingerprints when every file moves down", () => {
    for (const seed of SEEDS) {
      const files = randomProject(seed);
      const a = exportFiles(files);
      expect(exportFiles(files).text, `seed ${seed}`).toBe(a.text);
      const moved = exportFiles(shifted(files, 4));
      expect(moved.records.map((r) => r.fingerprint), `seed ${seed}`).toEqual(a.records.map((r) => r.fingerprint));
      a.records.forEach((r, i) => expect(moved.records[i]!.trace.map((t) => t.line), `seed ${seed} ${r.fingerprint}`).toEqual(r.trace.map((t) => t.line + 4)));
    }
  });

  it("never exports a path the format refuses, and never loses a finding without counting it", () => {
    for (const seed of SEEDS) {
      const files = randomProject(seed);
      const result = run(files);
      const exported = exportFindings(result);
      const left = exported.omitted.reduce((n, o) => n + o.count, 0);
      expect(exported.records.length + left, `seed ${seed}`).toBe(result.findings.length + result.suppressed.length);
      for (const r of exported.records) for (const s of [...r.trace, ...r.evidence]) expect(isSafePath(s.file), `seed ${seed}`).toBe(true);
    }
  });

  it("is stable when a comment line is inserted after the first line of every source file", () => {
    for (const seed of SEEDS.slice(0, 120)) {
      const files = randomProject(seed);
      const edited = Object.fromEntries(
        Object.entries(files).map(([path, text]) => {
          if (!/\.(?:ts|tsx|mjs)$/.test(path)) return [path, text];
          const at = text.indexOf("\n") + 1;
          return [path, `${text.slice(0, at)}// a comment that moves everything below it\n${text.slice(at)}`];
        }),
      );
      const a = exportFiles(files).records.map((r) => r.fingerprint);
      const b = exportFiles(edited).records.map((r) => r.fingerprint);
      expect(b, `seed ${seed}`).toEqual(a);
    }
  });
});

describe("cli: --findings", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  function project(files: Record<string, string>): string {
    const root = mkdtempSync(join(tmpdir(), "saas-audit-findings-"));
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
    return { code: runCli(args, io), out, err };
  }

  const FILES = { "app/api/notes/route.ts": OPEN_ROUTE, "supabase/migrations/001.sql": "create table public.notes (id int);\n" };

  it("prints the records, uses the exit codes of the other formats and is the same as the library output", () => {
    const root = project(FILES);
    const r = cli([root, "--findings"], tmpdir());
    expect(r.code).toBe(1);
    expect(r.err).toBe("");
    expect(conformanceErrorsOfText(r.out)).toEqual([]);
    const fingerprints = looseRecords(r.out).map((x) => x["fingerprint"]);
    expect(fingerprints).toEqual([
      "saas-audit/api-route-no-auth:app/api/notes/route.ts:GET+20handler",
      "saas-audit/supabase-rls-missing:supabase/migrations/001.sql:public.notes",
    ]);
    expect(cli([root, "--findings", "--fail-on", "none"], tmpdir()).code).toBe(0);
  });

  it("writes to a file with --output and prints an empty array for a clean project", () => {
    const root = project(FILES);
    const out = join(root, "..", `findings-${Date.now()}.json`);
    dirs.push(out);
    const r = cli([root, "--findings", "--output", out], tmpdir());
    expect(r.code).toBe(1);
    expect(r.out).toBe("");
    expect(conformanceErrorsOfText(readFileSync(out, "utf8"))).toEqual([]);
    const clean = project({ "README.md": "x\n" });
    expect(cli([clean, "--findings"], tmpdir())).toMatchObject({ code: 0, out: "[]\n" });
  });

  it("applies --min-severity and refuses to be combined with another format", () => {
    const root = project(FILES);
    expect(looseRecords(cli([root, "--findings", "--min-severity", "high"], tmpdir()).out)).toHaveLength(2);
    expect(looseRecords(cli([root, "--findings", "--min-severity", "critical"], tmpdir()).out)).toHaveLength(0);
    for (const other of ["--json", "--markdown"]) {
      const r = cli([root, "--findings", other], tmpdir());
      expect(r.code).toBe(2);
      expect(r.err).toContain("cannot be combined");
    }
    expect(cli(["--help"], tmpdir()).out).toContain("--findings");
  });

  it("reports on stderr a finding it has to leave out, without changing the exit code", () => {
    const root = project({ "app/api/a:b/route.ts": OPEN_ROUTE, "app/api/ok/route.ts": OPEN_ROUTE });
    const r = cli([root, "--findings"], tmpdir());
    expect(r.code).toBe(1);
    expect(r.err).toContain("1 finding left out");
    expect(r.err).toContain("repository-relative path");
    expect(looseRecords(r.out)).toHaveLength(1);
    expect(conformanceErrorsOfText(r.out)).toEqual([]);
  });

  it("exports a silenced finding as rejected", () => {
    const root = project({ "app/api/notes/route.ts": "// saas-audit-ignore-file api-route-no-auth -- public list\n" + OPEN_ROUTE });
    const r = cli([root, "--findings"], tmpdir());
    const records = looseRecords(r.out);
    expect(records.map((x) => x["verdict"])).toEqual(["rejected"]);
    expect(r.code).toBe(0);
  });
});
