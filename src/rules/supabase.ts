import { isConstantTrue, referencesColumn, type PolicyInfo, type TableInfo } from "../sql/model.js";
import { tokensToText, type Token } from "../sql/tokenizer.js";
import { normalizeColumn } from "../ts/calls.js";
import type { RawFinding, Severity } from "../types.js";
import { textLine, type AuditContext, type Rule } from "./context.js";

export const DEFAULT_TENANT_COLUMNS = ["user_id", "owner_id", "tenant_id", "org_id", "organization_id", "account_id", "team_id", "workspace_id", "created_by", "author_id"];

const SERVICE_ROLES: Record<string, true> = { service_role: true, postgres: true, supabase_admin: true, supabase_auth_admin: true };
const WRITE_COMMANDS: Record<string, true> = { all: true, insert: true, update: true, delete: true };

export function tenantColumnSet(extra: readonly string[]): Set<string> {
  return new Set([...DEFAULT_TENANT_COLUMNS, ...extra].map(normalizeColumn));
}

function ownerColumns(table: TableInfo, tenantSet: ReadonlySet<string>): string[] {
  return table.columns.filter((c) => c.refsAuthUsers || tenantSet.has(normalizeColumn(c.name))).map((c) => c.name);
}

function clauseText(label: string, expr: Token[] | null): string {
  return expr ? `${label} (${tokensToText(expr)})` : "";
}

function permissiveFinding(policy: PolicyInfo, table: TableInfo, hasOwnerColumn: boolean, ctx: AuditContext): RawFinding | null {
  if (!policy.permissive) return null;
  if (policy.roles.every((r) => SERVICE_ROLES[r])) return null;
  const writes = WRITE_COMMANDS[policy.command] === true;
  const exposedToAnon = policy.roles.includes("anon") || policy.roles.includes("public");
  const who = policy.roles.includes("public") ? "every role including anon" : policy.roles.join(", ");

  // which clause governs the command
  const using = policy.using;
  const check = policy.check ?? (policy.command === "all" || policy.command === "update" ? policy.using : null);
  let open = false;
  let clause = "";
  if (policy.command === "insert") {
    open = isConstantTrue(policy.check);
    clause = clauseText("WITH CHECK", policy.check);
  } else if (policy.command === "select" || policy.command === "delete") {
    open = isConstantTrue(using);
    clause = clauseText("USING", using);
  } else {
    open = isConstantTrue(using) || isConstantTrue(policy.check);
    clause = isConstantTrue(using) ? clauseText("USING", using) : clauseText("WITH CHECK", check);
  }

  const file = policy.file;
  const line = policy.line;
  const evidence = textLine(ctx.project.files.get(file) ?? "", line);
  const common = { file, line, evidence, rule: "supabase-policy-permissive" };

  if (open && writes) {
    const severity: Severity = exposedToAnon ? "critical" : "high";
    return {
      ...common,
      severity,
      title: `Policy "${policy.name}" lets ${who} ${policy.command === "all" ? "read and write" : policy.command} every row of ${table.name}`,
      message: `${clause} is always true, so row level security does not restrict ${policy.command === "all" ? "reads or writes" : policy.command + "s"} on ${table.name} for ${who}.${exposedToAnon ? " The anon key ships in every browser bundle, so anyone on the internet can use it." : ""}`,
      fix: `Replace the constant with a condition tied to the caller, for example auth.uid() = ${hasOwnerColumn ? "user_id" : "<owner column>"}, or drop the policy and add a narrower one.`,
    };
  }
  if (writes && policy.roles.includes("anon")) {
    return {
      ...common,
      severity: "high",
      title: `Policy "${policy.name}" allows the anon role to ${policy.command === "all" ? "write to" : policy.command} ${table.name}`,
      message: `The anon role is anyone holding the public anon key. ${clause || "The policy"} is the only thing standing between the internet and writes to ${table.name}.`,
      fix: "Grant write policies to the authenticated role and require auth.uid() in the expression. If anonymous writes are intended (a contact form), write through a server route with validation and rate limiting instead.",
    };
  }
  if (open) {
    return {
      ...common,
      severity: hasOwnerColumn ? "high" : "medium",
      title: `Policy "${policy.name}" lets ${who} read every row of ${table.name}`,
      message: `${clause} is always true.${hasOwnerColumn ? ` ${table.name} has an owner column, so this exposes every user's rows.` : " That is fine for genuinely public reference data and a leak for anything else."}`,
      fix: "Scope the policy to the caller (auth.uid() = owner column). If the table is public on purpose, keep the policy and add a saas-audit-ignore-next-line comment with the reason.",
    };
  }
  return null;
}

export const supabaseRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  const tenantSet = tenantColumnSet(ctx.config.tenantColumns);
  const policiesByTable = new Map<string, PolicyInfo[]>();
  for (const p of ctx.sql.policies) {
    const list = policiesByTable.get(p.table) ?? [];
    list.push(p);
    policiesByTable.set(p.table, list);
  }

  for (const [key, table] of ctx.sql.tables) {
    const owners = ownerColumns(table, tenantSet);
    const evidence = textLine(ctx.project.files.get(table.file) ?? "", table.line);
    const where = { file: table.file, line: table.line, evidence };
    if (!table.rlsEnabled) {
      out.push({
        ...where,
        rule: "supabase-rls-missing",
        severity: owners.length > 0 ? "critical" : "high",
        title: `Table ${table.schema}.${table.name} has no row level security`,
        message: `Tables in the public schema are exposed through the REST API to anyone with the anon key. Without ENABLE ROW LEVEL SECURITY every row can be read${owners.length > 0 ? ` (${table.name} has ${owners.join(", ")}, so these are per-user rows)` : ""} and, with the default grants, written.`,
        fix: `Add "alter table ${table.schema}.${table.name} enable row level security;" in a migration, then add policies for each operation the app needs.`,
      });
      continue;
    }
    const policies = (policiesByTable.get(key) ?? []).filter((p) => !p.roles.every((r) => SERVICE_ROLES[r]));
    if (policies.length === 0) {
      out.push({
        ...where,
        rule: "supabase-policy-missing",
        severity: "medium",
        title: `Table ${table.schema}.${table.name} has row level security but no policies`,
        message: "With RLS on and no policy, anon and authenticated clients are denied every operation. Either the table is only used through the service role, or the app is broken and the quick fix will be to switch RLS off or add a policy with USING (true).",
        fix: "Add one policy per operation the app needs, scoped with auth.uid(). If only server code touches the table, document that and suppress this finding.",
      });
      continue;
    }
    for (const policy of policies) {
      const f = permissiveFinding(policy, table, owners.length > 0, ctx);
      if (f) out.push(f);
    }
    if (owners.length > 0) {
      const scoped = policies.some((p) => p.permissive && owners.some((col) => referencesColumn(p.using, col) || referencesColumn(p.check, col)));
      if (!scoped) {
        out.push({
          ...where,
          rule: "supabase-tenant-unscoped",
          severity: "high",
          title: `No policy on ${table.name} references ${owners.join(" / ")}`,
          message: `${table.name} has ${owners.join(", ")} to identify who owns a row, but none of its ${policies.length} polic${policies.length === 1 ? "y mentions" : "ies mention"} it. Any user the policies admit can reach every other user's or tenant's rows.`,
          fix: `Add the owner column to the USING and WITH CHECK expressions, for example using (auth.uid() = ${owners[0]}) with check (auth.uid() = ${owners[0]}).`,
        });
      }
    }
  }
  return out;
};
