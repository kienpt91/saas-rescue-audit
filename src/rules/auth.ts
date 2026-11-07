import ts from "typescript";
import { compileGlobs } from "../glob.js";
import { extractFilters, extractWrites, findDataOps, normalizeColumn } from "../ts/calls.js";
import { calleeName, entryLabel, entrySite, findAll, isFunctionLike, lineOf, lineText, type Entry, type SourceInfo } from "../ts/source.js";
import { computeTaint, isTainted, seedNames } from "../ts/taint.js";
import type { RawFinding } from "../types.js";
import type { Rule } from "./context.js";
import { tenantColumnSet } from "./supabase.js";
import { isStripeWebhook } from "./stripe.js";

export const DEFAULT_AUTH_HELPERS = [
  "auth",
  "currentUser",
  "getUser",
  "getClaims",
  "getSession",
  "getServerSession",
  "getToken",
  "getAuth",
  "getCurrentUser",
  "getAuthUser",
  "getUserFromRequest",
  "requireAuth",
  "requireUser",
  "requireSession",
  "requireAdmin",
  "withAuth",
  "withApiAuth",
  "authenticate",
  "authorize",
  "protect",
  "verifyAuth",
  "verifyJwt",
  "verifyToken",
  "jwtVerify",
  "validateRequest",
  "validateSession",
  "verifySession",
  "assertAuthenticated",
  "checkAuth",
  "isAuthenticated",
  "ensureAuthenticated",
  // webhook and cron style authentication
  "timingSafeEqual",
];

const CREDENTIAL_HEADER = /^(?:authorization|x-[a-z-]*(?:secret|token|key|signature)|[a-z-]*-signature|x-api-key)$/i;

function credentialRead(fn: ts.Node): boolean {
  return (
    findAll(fn, (n): n is ts.StringLiteral => ts.isStringLiteral(n)).some((s) => CREDENTIAL_HEADER.test(s.text)) ||
    findAll(fn, (n): n is ts.PropertyAccessExpression => ts.isPropertyAccessExpression(n)).some((p) => p.name.text === "authorization")
  );
}

function callNames(node: ts.Node): string[] {
  return findAll(node, (n): n is ts.CallExpression => ts.isCallExpression(n)).map((c) => calleeName(c.expression));
}

/** Functions declared in the file, by name. */
function localFunctions(src: SourceInfo): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>();
  for (const stmt of src.sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name) out.set(stmt.name.text, stmt);
    else if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer && isFunctionLike(d.initializer)) out.set(d.name.text, d.initializer);
      }
    }
  }
  return out;
}

export function authNames(src: SourceInfo, extra: readonly string[]): Set<string> {
  const names = new Set([...DEFAULT_AUTH_HELPERS, ...extra]);
  const locals = localFunctions(src);
  // functions in this file that call a recognised helper count as helpers themselves
  for (let pass = 0; pass < 4; pass++) {
    let grew = false;
    for (const [name, fn] of locals) {
      if (!names.has(name) && callNames(fn).some((c) => names.has(c))) {
        names.add(name);
        grew = true;
      }
    }
    if (!grew) break;
  }
  return names;
}

function hasAuth(entry: Entry, names: ReadonlySet<string>): boolean {
  if (entry.wrappers.some((w) => names.has(w))) return true;
  if (callNames(entry.fn).some((c) => names.has(c))) return true;
  return credentialRead(entry.fn);
}

const dataHelperCache = new WeakMap<SourceInfo, Map<string, "read" | "write">>();

/** Same-file functions that touch the database, computed once per file. */
function dataHelpers(src: SourceInfo, extraRoots: readonly string[]): Map<string, "read" | "write"> {
  let helpers = dataHelperCache.get(src);
  if (!helpers) {
    helpers = new Map();
    for (const [name, fn] of localFunctions(src)) {
      const ops = findDataOps(fn, extraRoots);
      if (ops.length > 0) helpers.set(name, ops.some((o) => o.kind === "write") ? "write" : "read");
    }
    dataHelperCache.set(src, helpers);
  }
  return helpers;
}

function localDataOps(entry: Entry, src: SourceInfo, extraRoots: readonly string[]): { node: ts.Node; kind: "read" | "write" }[] {
  const direct = findDataOps(entry.fn, extraRoots).map((o) => ({ node: o.node, kind: o.kind }));
  const dataFns = dataHelpers(src, extraRoots);
  const viaHelpers = findAll(entry.fn, (n): n is ts.CallExpression => ts.isCallExpression(n))
    .filter((c) => ts.isIdentifier(c.expression) && dataFns.has(c.expression.text))
    .map((c) => ({ node: c as ts.Node, kind: dataFns.get((c.expression as ts.Identifier).text)! }));
  return [...direct, ...viaHelpers].sort((a, b) => a.node.getStart(src.sf) - b.node.getStart(src.sf));
}

const ID_COLUMN = /^(?:id|uuid|.+id)$/;

function idorFindings(src: SourceInfo, entry: Entry, owners: ReadonlySet<string>, extraRoots: readonly string[], out: RawFinding[]): void {
  const tainted = computeTaint(entry.fn, seedNames(entry));
  const isOwner = (col: string): boolean => owners.has(normalizeColumn(col));
  for (const op of findDataOps(entry.fn, extraRoots)) {
    if (op.via !== "db" || op.chain.links.length === 0) continue;
    const filters = extractFilters(op.chain);
    const idFilters = filters.filter((f) => !isOwner(f.column) && ID_COLUMN.test(normalizeColumn(f.column)) && isTainted(f.value, tainted));
    const clientOwner = filters.filter((f) => isOwner(f.column) && isTainted(f.value, tainted));
    const serverOwner = filters.filter((f) => isOwner(f.column) && !isTainted(f.value, tainted));
    const writesOwner = extractWrites(op.chain).filter((w) => isOwner(w.column) && isTainted(w.value, tainted));

    if ((idFilters.length > 0 || clientOwner.length > 0) && serverOwner.length === 0) {
      const f = (idFilters[0] ?? clientOwner[0])!;
      const line = lineOf(src.sf, f.value);
      const table = op.target ? ` on ${op.target}` : "";
      const title = `${op.kind === "write" ? "Write" : "Read"}${table} filtered only by ${f.column} from the request`;
      out.push({
        rule: "api-idor",
        severity: op.kind === "write" ? "high" : "medium",
        file: src.path,
        line,
        title,
        message: `The record is chosen by ${f.column}, which the caller controls, and the query has no filter on the signed-in user. Changing the id in the request reaches other users' records. If row level security already restricts this table to the owner and the query runs with the user's own client, this is defense in depth; with a service-role or admin client it is the only check.`,
        evidence: lineText(src.sf, line),
        fix: `Add an ownership condition taken from the session (for example .eq("user_id", user.id) or where: { id, userId: session.user.id }) and treat zero matched rows as 404.`,
        subject: [`${entryLabel(entry)}: ${title}`],
        entry: entrySite(src, entry),
      });
    }
    if (writesOwner.length > 0) {
      const w = writesOwner[0]!;
      const line = lineOf(src.sf, w.value);
      const title = `Row owner ${w.column} is set from the request`;
      out.push({
        rule: "api-idor",
        severity: "high",
        file: src.path,
        line,
        title,
        message: `The ${op.method} writes ${w.column} with a value supplied by the caller, so anyone can create or reassign rows for other users or tenants.`,
        evidence: lineText(src.sf, line),
        fix: `Set ${w.column} from the verified session (user.id) on the server and never read it from the body.`,
        subject: [`${entryLabel(entry)}: ${title}`],
        entry: entrySite(src, entry),
      });
    }
  }
}

export const authRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  const isPublic = compileGlobs(ctx.config.publicRoutes);
  const owners = new Set([...tenantColumnSet(ctx.config.tenantColumns), "uid", "user", "owner"]);
  for (const src of ctx.sources) {
    if (src.isClient || src.entries.length === 0) continue;
    ctx.guard(src.path, () => {
      const webhook = isStripeWebhook(src);
      const names = authNames(src, ctx.config.authHelpers);
      const publicRoute = isPublic(src.path);
      for (const entry of src.entries) {
        if (entry.kind === "page") continue;
        idorFindings(src, entry, owners, ctx.config.dataAccessRoots, out);
        if (webhook || hasAuth(entry, names)) continue;
        const ops = localDataOps(entry, src, ctx.config.dataAccessRoots);
        if (ops.length === 0) continue;
        const first = ops[0]!;
        const writes = ops.some((o) => o.kind === "write");
        const declLine = lineOf(src.sf, entry.decl);
        const opLine = lineOf(src.sf, first.node);
        out.push({
          rule: "api-route-no-auth",
          severity: writes ? "critical" : "high",
          file: src.path,
          line: declLine,
          title: `${entryLabel(entry)} ${writes ? "writes" : "reads"} data without an auth check`,
          message: `No call to a recognised auth helper (getUser, getSession, auth, requireUser, ...) was found in this ${entry.kind === "action" ? "server action" : "handler"}. ${entry.kind === "action" ? "Server actions are public POST endpoints regardless of where they are imported." : "Route handlers are reachable by anyone who knows the URL, and middleware alone is not a reliable gate."}`,
          evidence: declLine === opLine ? `L${declLine}: ${lineText(src.sf, declLine)}` : `L${declLine}: ${lineText(src.sf, declLine)}\nL${opLine}: ${lineText(src.sf, opLine)}`,
          fix: "Resolve the user at the top of the handler and return 401 when there is none, then scope every query to that user. If the route is public on purpose, list it in publicRoutes in saas-audit.config.json or add a saas-audit-ignore-file comment with the reason. Custom helpers can be added with authHelpers.",
          subject: [entryLabel(entry)],
          entry: entrySite(src, entry),
          sink: { file: src.path, line: opLine, note: `${writes ? "Database write" : "Database read"} reached without any recognised auth check`, text: lineText(src.sf, opLine) },
          ...(publicRoute ? { suppressedBy: "config publicRoutes" } : {}),
        });
      }
    });
  }
  return out;
};
