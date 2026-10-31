import { describe, expect, it } from "vitest";
import { redact } from "../src/redact.js";
import { detectKeyShape, shannonEntropy } from "../src/rules/secrets.js";
import { base64url, fakeKey, keys, of, randomToken, run } from "./helpers.js";

describe("secret-in-client: NEXT_PUBLIC_ names", () => {
  it("flags a service-role key published through NEXT_PUBLIC_", () => {
    const r = run({ "lib/supabase.ts": 'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);\n' });
    expect(keys(r)).toEqual(["secret-in-client@lib/supabase.ts:2"]);
    expect(r.findings[0]!.severity).toBe("critical");
    expect(r.findings[0]!.title).toContain("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY");
  });

  it("does not flag the anon key, the publishable key or other public names", () => {
    const r = run({
      "lib/env.ts": "export const a = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\nexport const b = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\nexport const c = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;\nexport const d = process.env.NEXT_PUBLIC_SITE_URL;\n",
    });
    expect(r.findings).toEqual([]);
  });

  it("flags secret-looking names in .env files without printing the value", () => {
    const r = run({ ".env.example": "NEXT_PUBLIC_WEBHOOK_SECRET=\nNEXT_PUBLIC_API_URL=https://example.test\n", ".gitignore": ".env*\n!.env.example\n" });
    expect(keys(r)).toEqual(["secret-in-client@.env.example:1"]);
    expect(r.findings[0]!.evidence).toBe("NEXT_PUBLIC_WEBHOOK_SECRET=…");
  });

  it("flags secret-looking keys in the next.config env block", () => {
    const r = run({ "next.config.mjs": 'export default {\n  env: {\n    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,\n    SITE: "x",\n  },\n};\n' });
    expect(keys(r).filter((k) => k.startsWith("secret-in-client"))).toEqual(["secret-in-client@next.config.mjs:3"]);
  });
});

describe("secret-in-client: client components", () => {
  const client = (body: string) => `"use client";\n${body}\n`;

  it("flags a server secret read in a client component", () => {
    const r = run({ "components/Admin.tsx": client("export function Admin() {\n  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n  return <div>{key}</div>;\n}") });
    expect(keys(r)).toEqual(["secret-in-client@components/Admin.tsx:3"]);
    expect(r.findings[0]!.severity).toBe("high");
  });

  it("catches bracket access and destructuring", () => {
    const r = run({ "components/A.tsx": client('const a = process.env["STRIPE_SECRET_KEY"];\nconst { DATABASE_URL } = process.env;\nexport const x = [a, DATABASE_URL];') });
    expect(keys(r)).toEqual(["secret-in-client@components/A.tsx:2", "secret-in-client@components/A.tsx:3"]);
  });

  it("does not flag the same read in a server file or a public variable in a client file", () => {
    const server = run({ "lib/stripe.ts": "export const k = process.env.STRIPE_SECRET_KEY;\n" });
    const publicVar = run({ "components/B.tsx": client("export const u = process.env.NEXT_PUBLIC_SUPABASE_URL;") });
    expect(server.findings).toEqual([]);
    expect(publicVar.findings).toEqual([]);
  });

  it("requires the directive to be at the top of the file", () => {
    const r = run({ "components/C.tsx": 'import x from "x";\n"use client";\nexport const k = process.env.STRIPE_SECRET_KEY;\n' });
    expect(r.findings).toEqual([]);
  });
});

describe("secret-hardcoded", () => {
  it("flags a Stripe live key and redacts it in the evidence", () => {
    const key = fakeKey("sk", "_live_", randomToken(24));
    const r = run({ "lib/stripe.ts": `import Stripe from "stripe";\nexport const stripe = new Stripe("${key}");\n` });
    expect(keys(r)).toEqual(["secret-hardcoded@lib/stripe.ts:2"]);
    expect(r.findings[0]!.severity).toBe("critical");
    expect(r.findings[0]!.evidence).not.toContain(key);
    expect(r.findings[0]!.evidence).toContain("sk_l…[32 chars]");
  });

  it("rates a Stripe test key medium", () => {
    const r = run({ "lib/s.ts": `export const k = "${fakeKey("sk", "_test_", randomToken(24, 2))}";\n` });
    expect(r.findings[0]).toMatchObject({ rule: "secret-hardcoded", severity: "medium" });
  });

  it("recognises AWS, GitHub, Slack, webhook-secret and private-key shapes", () => {
    const shapes: [string, string][] = [
      ["AWS", fakeKey("AK", "IA", "ABCDEFGHJKLMNPQR")],
      ["GitHub", fakeKey("gh", "p_", randomToken(36, 3))],
      ["Slack", fakeKey("xo", "xb-", randomToken(12, 4), "-", randomToken(12, 5))],
      ["webhook", fakeKey("wh", "sec_", randomToken(32, 6))],
      ["private key", fakeKey("-----BEGIN ", "RSA PRIV", "ATE KEY-----")],
    ];
    for (const [name, value] of shapes) {
      const hit = detectKeyShape(value);
      expect(hit, name).not.toBeNull();
    }
  });

  it("flags a service-role JWT but not an anon JWT", () => {
    const jwt = (role: string) => `${base64url({ alg: "HS256", typ: "JWT" })}.${base64url({ iss: "supabase", role })}.${randomToken(43, 7)}`;
    expect(detectKeyShape(jwt("service_role"))).toMatchObject({ label: "Supabase service-role JWT", severity: "critical" });
    expect(detectKeyShape(jwt("anon"))).toBeNull();
    const r = run({ "lib/a.ts": `export const k = "${jwt("service_role")}";\n` });
    expect(keys(r)).toEqual(["secret-hardcoded@lib/a.ts:1"]);
  });

  it("flags a database URL with a real password, not a placeholder", () => {
    const real = `postgres://app:${randomToken(16, 8)}@db.example.test:5432/app`;
    expect(detectKeyShape(real)).toMatchObject({ severity: "high", redacted: "[database password, 16 chars]" });
    expect(JSON.stringify(detectKeyShape(real))).not.toContain(real.split(":")[2]!.split("@")[0]!);
    expect(detectKeyShape("postgresql://postgres:postgres@localhost:5432/dev")).toBeNull();
  });

  it("flags high-entropy values assigned to secret-looking names only", () => {
    const value = fakeKey(randomToken(10, 9), "7", randomToken(10, 10));
    const named = run({ "lib/cron.ts": `export const cronToken = "${value}";\n` });
    const neutral = run({ "lib/cron.ts": `export const slug = "${value}";\n` });
    expect(keys(named)).toEqual(["secret-hardcoded@lib/cron.ts:1"]);
    expect(named.findings[0]!.severity).toBe("medium");
    expect(named.findings[0]!.evidence).not.toContain(value);
    expect(neutral.findings).toEqual([]);
  });

  it("ignores placeholders, sentences, URLs and low-entropy strings", () => {
    const r = run({
      "lib/ok.ts": [
        'export const apiKey = "your-api-key-goes-here-123456";',
        'export const secretLabel = "this is a human readable sentence 123";',
        'export const tokenUrl = "https://auth.example.test/oauth/token?x=1234567890";',
        'export const password = "aaaaaaaaaaaaaaaaaaaaaaaa1";',
        "",
      ].join("\n"),
    });
    expect(r.findings).toEqual([]);
  });

  it("measures entropy sensibly and redacts to a prefix and a length", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
    expect(shannonEntropy("abababab")).toBeCloseTo(1, 5);
    expect(shannonEntropy(randomToken(40, 11))).toBeGreaterThan(4);
    expect(redact("abcdefghijkl")).toBe("abcd…[12 chars]");
  });

  it("flags a real-looking key in .env.example", () => {
    const key = fakeKey("sk", "_live_", randomToken(24, 12));
    const r = run({ ".env.example": `STRIPE_SECRET_KEY=${key}\n`, ".gitignore": ".env*\n!.env.example\n" });
    expect(keys(r)).toEqual(["secret-hardcoded@.env.example:1"]);
    expect(r.findings[0]!.evidence).not.toContain(key);
  });
});

describe("secret-committed-env", () => {
  it("flags an .env file that no .gitignore covers", () => {
    const r = run({ ".env.local": "SUPABASE_SERVICE_ROLE_KEY=placeholder-value\nSTRIPE_SECRET_KEY=abc-def-123\n" });
    const f = of(r, "secret-committed-env");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ file: ".env.local", line: 1, severity: "high" });
    expect(f[0]!.title).toContain("the project has no .gitignore");
    expect(f[0]!.message).toContain("STRIPE_SECRET_KEY");
    expect(f[0]!.evidence).toBe("STRIPE_SECRET_KEY=…");
    expect(JSON.stringify(f[0])).not.toContain("abc-def-123");
  });

  it("is quiet when .gitignore covers the file", () => {
    const r = run({ ".env.local": "STRIPE_SECRET_KEY=abc-def-123\n", ".gitignore": ".env*\n" });
    expect(r.findings).toEqual([]);
  });

  it("never flags template files", () => {
    const r = run({ ".env.example": "STRIPE_SECRET_KEY=\n", ".env.sample": "A=\n", ".env.local.template": "A=\n" });
    expect(r.findings).toEqual([]);
  });

  it("rates a file holding only placeholders as medium", () => {
    const r = run({ ".env": "STRIPE_SECRET_KEY=your-secret-here\nNODE_ENV=production\n" });
    expect(of(r, "secret-committed-env")[0]!.severity).toBe("medium");
  });

  it("treats a file in the git index as tracked and critical even when .gitignore lists it", () => {
    const r = run({ ".env.production": "DATABASE_URL=postgres-host-123\n", ".gitignore": ".env*\n" }, { tracked: [".env.production", ".gitignore"] });
    const f = of(r, "secret-committed-env");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical" });
    expect(f[0]!.title).toContain("tracked by git");
    expect(f[0]!.fix).toContain("git rm --cached -- '.env.production'");
  });

  it("with an index, an ignored and untracked file is fine, an unignored untracked one is not", () => {
    const ignored = run({ ".env": "A_SECRET=1234\n", ".gitignore": ".env\n" }, { tracked: [".gitignore"] });
    const open = run({ ".env": "A_SECRET=1234\n" }, { tracked: [] });
    expect(ignored.findings).toEqual([]);
    expect(of(open, "secret-committed-env")).toHaveLength(1);
  });

  it("checks nested env files against nested .gitignore files", () => {
    const r = run({ "apps/web/.env.local": "A_SECRET=1234\n", "apps/web/.gitignore": ".env.local\n", "apps/api/.env.local": "A_SECRET=1234\n" });
    expect(keys(r)).toEqual(["secret-committed-env@apps/api/.env.local:1"]);
  });
});
