import { describe, expect, it } from "vitest";
import { buildSqlModel, isConstantTrue, referencesColumn } from "../src/sql/model.js";
import { tokenize, tokensToText } from "../src/sql/tokenizer.js";

const values = (sql: string): string[] => tokenize(sql).map((t) => t.value);

describe("sql tokenizer", () => {
  it("splits words, punctuation and operators with 1-based lines", () => {
    const toks = tokenize("create table t (\n  id int = 1\n);");
    expect(toks.map((t) => t.text)).toEqual(["create", "table", "t", "(", "id", "int", "=", "1", ")", ";"]);
    expect(toks[0]!.line).toBe(1);
    expect(toks.find((t) => t.text === "id")!.line).toBe(2);
    expect(toks.at(-1)!.line).toBe(3);
  });

  it("drops line comments and nested block comments", () => {
    expect(values("select 1 -- enable row level security\n, 2 /* a /* nested */ still comment */ , 3")).toEqual(["select", "1", ",", "2", ",", "3"]);
  });

  it("keeps keywords inside strings out of the token stream and handles doubled quotes", () => {
    const toks = tokenize("select 'it''s; alter table' as x");
    expect(toks.map((t) => t.kind)).toEqual(["word", "string", "word", "word"]);
    expect(toks[1]!.value).toBe("it's; alter table");
  });

  it("treats dollar-quoted bodies as one token even when they contain semicolons", () => {
    const toks = tokenize("create function f() returns void as $body$ begin perform 1; end; $body$ language plpgsql;");
    const dollar = toks.filter((t) => t.kind === "dollar");
    expect(dollar).toHaveLength(1);
    expect(dollar[0]!.value).toContain("perform 1;");
    expect(toks.filter((t) => t.text === ";")).toHaveLength(1);
  });

  it("keeps quoted identifier case and unescapes doubled double quotes", () => {
    const [tok] = tokenize('"My ""Table"""');
    expect(tok!.kind).toBe("qident");
    expect(tok!.value).toBe('My "Table"');
  });

  it("handles E-strings with backslash escapes", () => {
    const toks = tokenize("select E'a\\'b;' , 2");
    expect(toks.map((t) => t.kind)).toEqual(["word", "string", "punct", "number"]);
  });

  it("does not throw on unterminated strings or comments", () => {
    expect(() => tokenize("select 'oops")).not.toThrow();
    expect(() => tokenize("select /* oops")).not.toThrow();
  });

  it("renders tokens back to compact text", () => {
    const toks = tokenize("(auth.uid() = user_id)");
    expect(tokensToText(toks)).toBe("(auth.uid() = user_id)");
  });
});

describe("sql model", () => {
  const model = (sql: string, path = "supabase/migrations/001.sql") => buildSqlModel([{ path, text: sql }]);

  it("registers public tables, defaulting an unqualified name to public", () => {
    const m = model("create table notes (id uuid primary key);\ncreate table public.tags (id int);");
    expect([...m.tables.keys()]).toEqual(["public.notes", "public.tags"]);
    expect(m.tables.get("public.notes")!.line).toBe(1);
    expect(m.tables.get("public.tags")!.line).toBe(2);
  });

  it("ignores tables in other schemas and temporary tables", () => {
    const m = model("create table private.secrets (id int);\ncreate temp table scratch (id int);\ncreate table if not exists app.x (id int);");
    expect(m.tables.size).toBe(0);
  });

  it("parses columns, skips table constraints and notices references to auth.users", () => {
    const m = model(`create table public.projects (
      id uuid primary key,
      owner uuid references auth.users (id) on delete cascade,
      name text not null,
      org uuid,
      constraint projects_org_fk foreign key (org) references auth.users(id),
      unique (name)
    );`);
    const t = m.tables.get("public.projects")!;
    expect(t.columns.map((c) => c.name)).toEqual(["id", "owner", "name", "org"]);
    expect(t.columns.find((c) => c.name === "owner")!.refsAuthUsers).toBe(true);
    expect(t.columns.find((c) => c.name === "org")!.refsAuthUsers).toBe(true);
    expect(t.columns.find((c) => c.name === "name")!.refsAuthUsers).toBe(false);
  });

  it("tracks ENABLE and DISABLE ROW LEVEL SECURITY, including if exists and only", () => {
    const m = model(`create table a (id int); create table b (id int); create table c (id int);
      alter table a enable row level security;
      alter table if exists only public.b enable row level security, add column x int;
      alter table c enable row level security;
      alter table c disable row level security;`);
    expect(m.tables.get("public.a")!.rlsEnabled).toBe(true);
    expect(m.tables.get("public.b")!.rlsEnabled).toBe(true);
    expect(m.tables.get("public.c")!.rlsEnabled).toBe(false);
    expect(m.tables.get("public.b")!.columns.map((c) => c.name)).toContain("x");
  });

  it("does not treat a comment or string as an RLS statement", () => {
    const m = model("create table a (id int);\n-- alter table a enable row level security;\nselect 'alter table a enable row level security';");
    expect(m.tables.get("public.a")!.rlsEnabled).toBe(false);
  });

  it("parses policies: command, roles, permissive flag and both expressions", () => {
    const m = model(`create policy "own rows" on public.notes as restrictive for update to authenticated, service_role
      using (auth.uid() = user_id) with check (auth.uid() = user_id);`);
    const p = m.policies[0]!;
    expect(p.name).toBe("own rows");
    expect(p.table).toBe("public.notes");
    expect(p.command).toBe("update");
    expect(p.roles).toEqual(["authenticated", "service_role"]);
    expect(p.permissive).toBe(false);
    expect(tokensToText(p.using!)).toBe("auth.uid() = user_id");
    expect(tokensToText(p.check!)).toBe("auth.uid() = user_id");
  });

  it("defaults policy command to all and roles to public", () => {
    const m = model("create policy p on notes using (true);");
    expect(m.policies[0]).toMatchObject({ command: "all", roles: ["public"], permissive: true });
  });

  it("applies DROP POLICY, ALTER POLICY and DROP TABLE", () => {
    const m = model(`create table a (id int); create table b (id int);
      create policy p1 on a using (true); create policy p2 on a using (true); create policy p3 on b using (true);
      drop policy if exists p1 on a;
      alter policy p2 on a using (auth.uid() = id);
      drop table b;`);
    expect(m.policies.map((p) => p.name)).toEqual(["p2"]);
    expect(isConstantTrue(m.policies[0]!.using)).toBe(false);
    expect(m.tables.has("public.b")).toBe(false);
  });

  it("applies migrations in file name order, so a later one can enable RLS", () => {
    const m = buildSqlModel([
      { path: "supabase/migrations/002_rls.sql", text: "alter table public.a enable row level security;" },
      { path: "supabase/migrations/001_init.sql", text: "create table public.a (id int);" },
    ]);
    expect(m.tables.get("public.a")!.rlsEnabled).toBe(true);
    expect(m.tables.get("public.a")!.file).toBe("supabase/migrations/001_init.sql");
  });

  it("recognises constant-true expressions and nothing else", () => {
    const expr = (s: string) => tokenize(s);
    expect(isConstantTrue(expr("true"))).toBe(true);
    expect(isConstantTrue(expr("(TRUE)"))).toBe(true);
    expect(isConstantTrue(expr("((true))"))).toBe(true);
    expect(isConstantTrue(expr("1 = 1"))).toBe(true);
    expect(isConstantTrue(expr("auth.uid() = user_id"))).toBe(false);
    expect(isConstantTrue(expr("(true) and owner = 1"))).toBe(false);
    expect(isConstantTrue(null)).toBe(false);
  });

  it("finds column references case-insensitively", () => {
    const toks = tokenize("auth.uid() = USER_ID");
    expect(referencesColumn(toks, "user_id")).toBe(true);
    expect(referencesColumn(toks, "owner_id")).toBe(false);
    expect(referencesColumn(null, "user_id")).toBe(false);
  });
});
