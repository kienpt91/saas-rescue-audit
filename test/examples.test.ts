import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { RULES } from "../src/catalog.js";
import { run, type Io } from "../src/cli.js";
import { parseConfig } from "../src/config.js";
import { collectProject } from "../src/project.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { TOOL_VERSION } from "../src/version.js";
import { keys } from "./helpers.js";

const dir = (name: string): string => fileURLToPath(new URL(`../examples/${name}`, import.meta.url));

function auditExample(name: string) {
  const root = dir(name);
  let config = parseConfig("{}");
  try {
    config = parseConfig(readFileSync(`${root}/saas-audit.config.json`, "utf8"));
  } catch {
    // the flawed app has no config
  }
  return audit(collectProject(root, config), config);
}

const EXPECTED_VIBE_APP = [
  "api-idor@app/actions.ts:6",
  "api-idor@app/api/projects/[id]/route.ts:10",
  "api-idor@app/api/projects/route.ts:13",
  "api-route-no-auth@app/actions.ts:5",
  "api-route-no-auth@app/api/checkout/route.ts:6",
  "api-route-no-auth@app/api/projects/route.ts:4",
  "api-route-no-auth@app/api/projects/route.ts:9",
  "api-route-no-auth@app/api/public-notes/route.ts:4",
  "build-checks-disabled@next.config.mjs:4",
  "build-checks-disabled@next.config.mjs:5",
  "cors-wildcard-credentials@app/api/public-notes/route.ts:11",
  "deps-unpinned@package.json:1",
  "deps-unpinned@package.json:10",
  "deps-unpinned@package.json:11",
  "no-rate-limit@app/api/auth/callback/route.ts:4",
  "no-rate-limit@app/api/stripe/webhook/route.ts:7",
  "open-redirect@app/api/auth/callback/route.ts:13",
  "secret-committed-env@.env.local:1",
  "secret-in-client@.env.local:3",
  "secret-in-client@app/dashboard/page.tsx:14",
  "secret-in-client@lib/supabase.ts:6",
  "security-headers@next.config.mjs:1",
  "stripe-checkout-client-price@app/api/checkout/route.ts:16",
  "stripe-customer-unchecked@app/api/checkout/route.ts:11",
  "stripe-webhook-no-idempotency@app/api/stripe/webhook/route.ts:10",
  "stripe-webhook-parse-before-verify@app/api/stripe/webhook/route.ts:8",
  "stripe-webhook-unknown-event-error@app/api/stripe/webhook/route.ts:34",
  "supabase-policy-missing@supabase/migrations/0001_init.sql:17",
  "supabase-policy-permissive@supabase/migrations/0002_policies.sql:17",
  "supabase-policy-permissive@supabase/migrations/0002_policies.sql:22",
  "supabase-policy-permissive@supabase/migrations/0002_policies.sql:9",
  "supabase-rls-missing@supabase/migrations/0001_init.sql:24",
  "supabase-tenant-unscoped@supabase/migrations/0001_init.sql:10",
  "unsafe-html@components/Comment.tsx:2",
];

describe("examples/vibe-app (deliberately flawed)", () => {
  const result = auditExample("vibe-app");

  it("produces exactly the expected findings", () => {
    expect(keys(result)).toEqual(EXPECTED_VIBE_APP);
  });

  it("has no suppressions and no warnings", () => {
    expect(result.suppressed).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("counts by severity", () => {
    const counts: Record<string, number> = {};
    for (const f of result.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    expect(counts).toEqual({ critical: 7, high: 14, medium: 6, low: 4, info: 3 });
  });

  it("exercises these rules, and leaves only the rules that need other fixtures untested here", () => {
    const hit = new Set(result.findings.map((f) => f.rule));
    const missed = RULES.map((r) => r.id).filter((id) => !hit.has(id));
    expect(missed).toEqual(["secret-hardcoded", "stripe-webhook-unverified"]);
  });

  it("never prints a secret value in any finding", () => {
    const text = JSON.stringify(result.findings);
    expect(text).not.toContain("replace-with-service-role-key");
    expect(text).not.toContain("replace-with-stripe-secret-key");
  });
});

describe("examples/vibe-app-fixed", () => {
  const result = auditExample("vibe-app-fixed");

  it("is clean", () => {
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("does not count three findings: two silenced by inline comments with a reason, one by the config", () => {
    expect(result.suppressed.map((f) => `${f.rule}@${f.file}:${f.line} (${f.suppressedBy})`).sort()).toEqual([
      "deps-unpinned@package.json:1 (config ignoreRules)",
      "supabase-policy-missing@supabase/migrations/0001_init.sql:43 (inline comment)",
      "supabase-policy-permissive@supabase/migrations/0002_rls.sql:53 (inline comment)",
    ]);
    const root = dir("vibe-app-fixed");
    for (const f of result.suppressed.filter((s) => s.suppressedBy === "inline comment")) {
      const lines = readFileSync(`${root}/${f.file}`, "utf8").split("\n");
      expect(lines[f.line - 2]).toMatch(/saas-audit-ignore-next-line \S+ -- \S+/);
    }
  });

  it("parses every table and policy it ships", () => {
    expect(result.stats).toMatchObject({ tablesFound: 7, policiesFound: 10, routeHandlers: 6, serverActions: 1, clientComponents: 1 });
  });
});

describe("sample report", () => {
  it("is exactly what the CLI generates for examples/vibe-app", () => {
    const flawed = auditExample("vibe-app");
    const expected = renderMarkdown(flawed, { name: "vibe-app", version: TOOL_VERSION });
    expect(readFileSync(dir("sample-report.md"), "utf8")).toBe(expected);
  });

  it("is reproduced by the command documented in the README", () => {
    let out = "";
    const io: Io = { stdout: (t) => (out += t), stderr: () => undefined, cwd: fileURLToPath(new URL("..", import.meta.url)), color: false };
    expect(run(["examples/vibe-app", "--markdown"], io)).toBe(1);
    expect(out).toBe(readFileSync(dir("sample-report.md"), "utf8"));
  });

  it("has the sections of a client deliverable", () => {
    const md = readFileSync(dir("sample-report.md"), "utf8");
    for (const heading of ["# Security audit report: vibe-app", "## Summary", "## Findings at a glance", "## Findings", "## What was not checked", "## Rules applied"]) {
      expect(md).toContain(heading);
    }
    expect(md).toContain("| **Total** | **34** |");
  });
});

describe("cli on the examples", () => {
  const io = (cwd: string): { io: Io; out: () => string } => {
    let out = "";
    return { io: { stdout: (t) => (out += t), stderr: () => undefined, cwd, color: false }, out: () => out };
  };

  it("exits 1 for the flawed app and 0 for the fixed one", () => {
    expect(run([dir("vibe-app")], io(dir("")).io)).toBe(1);
    expect(run([dir("vibe-app-fixed")], io(dir("")).io)).toBe(0);
  });

  it("reports the same finding set in --json", () => {
    const { io: i, out } = io(dir(""));
    run([dir("vibe-app"), "--json"], i);
    const doc = JSON.parse(out());
    expect(doc.summary.bySeverity).toEqual({ critical: 7, high: 14, medium: 6, low: 4, info: 3 });
    expect(doc.findings).toHaveLength(34);
  });
});
