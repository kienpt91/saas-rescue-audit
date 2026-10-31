import { describe, expect, it } from "vitest";
import { keys, of, run } from "./helpers.js";

const M = "supabase/migrations/001_init.sql";
const sql = (text: string, extra: Record<string, string> = {}) => run({ [M]: text, ...extra });

describe("supabase-rls-missing", () => {
  it("flags a table without RLS at the CREATE TABLE line", () => {
    const r = sql("-- schema\ncreate table public.notes (\n  id uuid primary key,\n  body text\n);\n");
    expect(keys(r)).toEqual([`supabase-rls-missing@${M}:2`]);
    expect(r.findings[0]!.severity).toBe("high");
    expect(r.findings[0]!.evidence).toBe("create table public.notes (");
  });

  it("is critical when the table has an owner column", () => {
    const r = sql("create table notes (id uuid primary key, user_id uuid, body text);");
    expect(of(r, "supabase-rls-missing")[0]!.severity).toBe("critical");
    expect(of(r, "supabase-rls-missing")[0]!.message).toContain("user_id");
  });

  it("treats a column that references auth.users as an owner column whatever its name", () => {
    const r = sql("create table notes (id uuid primary key, author uuid references auth.users(id));");
    expect(of(r, "supabase-rls-missing")[0]!.severity).toBe("critical");
  });

  it("is quiet when RLS is enabled in the same migration", () => {
    const r = sql("create table notes (id int);\nalter table notes enable row level security;\ncreate policy p on notes for select to authenticated using (auth.uid() is not null);");
    expect(of(r, "supabase-rls-missing")).toEqual([]);
  });

  it("is quiet when a later migration enables RLS", () => {
    const r = sql("create table notes (id int);", { "supabase/migrations/002_rls.sql": "alter table notes enable row level security;" });
    expect(of(r, "supabase-rls-missing")).toEqual([]);
  });

  it("flags again when a later migration disables RLS", () => {
    const r = sql("create table notes (id int);\nalter table notes enable row level security;", { "supabase/migrations/002_oops.sql": "alter table notes disable row level security;" });
    expect(keys(r)).toContain(`supabase-rls-missing@${M}:1`);
  });

  it("ignores private-schema tables and tables that were dropped", () => {
    const r = sql("create table private.audit (id int);\ncreate table gone (id int);\ndrop table gone;");
    expect(r.findings).toEqual([]);
  });

  it("reads supabase/schema.sql too", () => {
    const r = run({ "supabase/schema.sql": "create table a (id int);" });
    expect(keys(r)).toEqual(["supabase-rls-missing@supabase/schema.sql:1"]);
  });

  it("does not look at SQL outside supabase/", () => {
    const r = run({ "db/seed.sql": "create table a (id int);" });
    expect(r.findings).toEqual([]);
  });
});

describe("supabase-policy-missing", () => {
  it("flags RLS with no policy", () => {
    const r = sql("create table t (id int);\nalter table t enable row level security;");
    expect(keys(r)).toEqual([`supabase-policy-missing@${M}:1`]);
    expect(r.findings[0]!.severity).toBe("medium");
  });

  it("does not count policies that only target service_role", () => {
    const r = sql("create table t (id int);\nalter table t enable row level security;\ncreate policy s on t to service_role using (true) with check (true);");
    expect(keys(r)).toEqual([`supabase-policy-missing@${M}:1`]);
  });

  it("is quiet once any client-role policy exists", () => {
    const r = sql("create table t (id int);\nalter table t enable row level security;\ncreate policy r on t for select to authenticated using (auth.uid() is not null);");
    expect(of(r, "supabase-policy-missing")).toEqual([]);
  });
});

const T = "create table t (id int primary key, user_id uuid);\nalter table t enable row level security;\n";

describe("supabase-policy-permissive", () => {
  it("flags USING (true) on ALL for authenticated as high", () => {
    const r = sql(T + "create policy everything on t for all to authenticated using (true) with check (true);");
    const f = of(r, "supabase-policy-permissive");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", line: 3, file: M });
    expect(f[0]!.title).toContain("read and write");
  });

  it("is critical when the anon role can use it, explicitly or through the default PUBLIC", () => {
    const explicit = sql(T + "create policy p on t for all to anon using (true);");
    const implicit = sql(T + "create policy p on t for insert with check (true);");
    expect(of(explicit, "supabase-policy-permissive")[0]!.severity).toBe("critical");
    expect(of(implicit, "supabase-policy-permissive")[0]!.severity).toBe("critical");
    expect(of(implicit, "supabase-policy-permissive")[0]!.message).toContain("anon key");
  });

  it("judges INSERT by WITH CHECK and UPDATE by either clause", () => {
    const ok = sql(T + "create policy i on t for insert to authenticated with check (auth.uid() = user_id);");
    const bad = sql(T + "create policy u on t for update to authenticated using (auth.uid() = user_id) with check (true);");
    expect(of(ok, "supabase-policy-permissive")).toEqual([]);
    expect(of(bad, "supabase-policy-permissive")[0]).toMatchObject({ severity: "high", line: 3 });
  });

  it("flags a public-read policy: high with an owner column, medium without", () => {
    const owned = sql(T + "create policy r on t for select using (true);");
    const plain = sql("create table c (id int);\nalter table c enable row level security;\ncreate policy r on c for select using (true);");
    expect(of(owned, "supabase-policy-permissive")[0]!.severity).toBe("high");
    expect(of(plain, "supabase-policy-permissive")[0]!.severity).toBe("medium");
  });

  it("flags an explicit anon write policy even when the expression looks restrictive", () => {
    const r = sql(T + "create policy anon_insert on t for insert to anon with check (user_id is not null);");
    const f = of(r, "supabase-policy-permissive");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high" });
    expect(f[0]!.title).toContain("anon role");
  });

  it("does not flag an anon SELECT with a real condition, or a PUBLIC write tied to auth.uid()", () => {
    const r = sql(T + "create policy a on t for select to anon using (user_id is null);\ncreate policy b on t for insert with check (auth.uid() = user_id);");
    expect(of(r, "supabase-policy-permissive")).toEqual([]);
  });

  it("ignores service_role, restrictive policies and 1 = 1 style is still caught", () => {
    const service = sql(T + "create policy s on t to service_role using (true);");
    const restrictive = sql(T + "create policy r on t as restrictive for all using (true);");
    const tautology = sql(T + "create policy x on t for delete to authenticated using (1 = 1);");
    expect(of(service, "supabase-policy-permissive")).toEqual([]);
    expect(of(restrictive, "supabase-policy-permissive")).toEqual([]);
    expect(of(tautology, "supabase-policy-permissive")).toHaveLength(1);
  });

  it("does not report policies on a table that has RLS switched off, only the missing RLS", () => {
    const r = sql("create table t (id int);\ncreate policy p on t using (true);");
    expect(keys(r)).toEqual([`supabase-rls-missing@${M}:1`]);
  });
});

describe("supabase-tenant-unscoped", () => {
  it("flags an owner column that no policy mentions", () => {
    const r = sql(T + "create policy auth_only on t for select to authenticated using (auth.role() = 'authenticated');");
    const f = of(r, "supabase-tenant-unscoped");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", line: 1 });
    expect(f[0]!.title).toContain("user_id");
  });

  it("is quiet when a policy references the owner column, directly or through a helper function", () => {
    const direct = sql(T + "create policy p on t for select to authenticated using (auth.uid() = user_id);");
    const helper = sql("create table t (id int, org_id uuid);\nalter table t enable row level security;\ncreate policy p on t for select to authenticated using (is_member(org_id));");
    expect(of(direct, "supabase-tenant-unscoped")).toEqual([]);
    expect(of(helper, "supabase-tenant-unscoped")).toEqual([]);
  });

  it("uses tenantColumns from the config", () => {
    const text = "create table t (id int, workspace_ref uuid);\nalter table t enable row level security;\ncreate policy p on t for select to authenticated using (auth.uid() is not null);";
    expect(of(run({ [M]: text }), "supabase-tenant-unscoped")).toEqual([]);
    expect(of(run({ [M]: text }, { config: { tenantColumns: ["workspace_ref"] } }), "supabase-tenant-unscoped")).toHaveLength(1);
  });

  it("recognises a profile table keyed by auth.users", () => {
    const r = sql("create table profiles (id uuid primary key references auth.users(id), name text);\nalter table profiles enable row level security;\ncreate policy p on profiles for select to authenticated using (auth.uid() = id);");
    expect(r.findings).toEqual([]);
  });
});

describe("supabase notes", () => {
  it("explains that RLS was not assessed when a Supabase project has no migrations", () => {
    const r = run({ "lib/db.ts": 'import { createClient } from "@supabase/supabase-js";\nexport const db = createClient("u", "k");\n' });
    expect(r.notes[0]).toContain("row level security was not assessed");
  });
});
