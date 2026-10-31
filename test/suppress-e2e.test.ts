import { describe, expect, it } from "vitest";
import { run } from "./helpers.js";

describe("suppression comments through the whole audit", () => {
  it("works in SQL with a -- reason and keeps the finding in `suppressed`", () => {
    const result = run({
      "supabase/migrations/001.sql": "-- saas-audit-ignore-next-line supabase-rls-missing -- public catalogue\ncreate table public.plans (id int primary key);\n",
    });
    expect(result.findings).toEqual([]);
    expect(result.suppressed.map((f) => f.rule)).toEqual(["supabase-rls-missing"]);
    expect(result.warnings).toEqual([]);
  });

  it("works in TSX with a JSX comment", () => {
    const result = run({
      "components/Post.tsx": [
        "export function Post({ html }: { html: string }) {",
        "  return (",
        "    <div>",
        "      {/* saas-audit-ignore-next-line unsafe-html -- html is sanitized upstream */}",
        "      <p dangerouslySetInnerHTML={{ __html: html }} />",
        "    </div>",
        "  );",
        "}",
        "",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
    expect(result.suppressed.map((f) => f.rule)).toEqual(["unsafe-html"]);
  });

  it("suppresses a whole file for one rule only", () => {
    const result = run({
      "app/api/a/route.ts": [
        "// saas-audit-ignore-file api-route-no-auth -- public read-only endpoint",
        "export async function GET() {",
        '  const { data } = await supabase.from("plans").select("*");',
        "  return Response.json(data);",
        "}",
        "export async function DELETE() {",
        '  await supabase.from("plans").delete().eq("id", 1);',
        "  return new Response(null);",
        "}",
        "",
      ].join("\n"),
    });
    expect(result.findings).toEqual([]);
    expect(result.suppressed.map((f) => f.rule)).toEqual(["api-route-no-auth", "api-route-no-auth"]);
  });

  it("does not warn about unused directives for rules switched off in the config", () => {
    const result = run({ "a.ts": "// saas-audit-ignore-file no-rate-limit\nexport const x = 1;\n" }, { config: { ignoreRules: ["no-rate-limit"] } });
    expect(result.warnings).toEqual([]);
  });
});
