/**
 * Recognises database and Stripe calls in method chains such as
 * `supabase.from("t").select().eq("id", id)` or `prisma.project.findMany({ where })`.
 */
import ts from "typescript";
import { tick } from "../limits.js";
import { unwrap } from "./source.js";

export interface Link {
  name: string;
  args: readonly ts.Expression[];
}

export interface Chain {
  terminal: ts.Node;
  /** Identifier at the start of the chain (`supabase`, or `createClient` for `createClient().from()`), else "". */
  rootName: string;
  links: Link[];
}

export type OpKind = "read" | "write";

export interface DataOp {
  kind: OpKind;
  node: ts.Node;
  chain: Chain;
  via: "db" | "stripe";
  /** Table or Stripe resource when it can be read from the call. */
  target: string;
  method: string;
}

const ROOT_NAMES =
  "supabase\\w*|admin\\w*|db|database|prisma|sql|knex|drizzle|pool|dbClient|createClient|createServerClient|createServiceClient|createAdminClient|createRouteHandlerClient|createServerComponentClient|getSupabase\\w*|getDb|getPrisma|createSupabase\\w*";
const NOT_A_DATABASE = /^(?:Array|Buffer|Object|Uint8Array|String|Promise|Set|Map|Date|JSON|Math|Number|URL|FormData|Headers)$/;

const WRITE_METHODS: Record<string, true> = {
  insert: true,
  update: true,
  upsert: true,
  delete: true,
  create: true,
  createMany: true,
  updateMany: true,
  deleteMany: true,
  upload: true,
  remove: true,
  del: true,
  $executeRaw: true,
  $executeRawUnsafe: true,
};

const READ_METHODS: Record<string, true> = {
  select: true,
  findMany: true,
  findFirst: true,
  findUnique: true,
  findFirstOrThrow: true,
  findUniqueOrThrow: true,
  findOne: true,
  findAll: true,
  findById: true,
  count: true,
  aggregate: true,
  groupBy: true,
  query: true,
  execute: true,
  $queryRaw: true,
  $queryRawUnsafe: true,
  raw: true,
  download: true,
};

const STRIPE_WRITES: Record<string, true> = { create: true, update: true, del: true, cancel: true, capture: true, confirm: true, pay: true, finalizeInvoice: true };
const STRIPE_READS: Record<string, true> = { retrieve: true, list: true, search: true };
const RPC_WRITE = /insert|update|delete|create|set|add|remove|upsert|grant|revoke/i;

export function isChainTerminal(call: ts.CallExpression): boolean {
  const p = call.parent;
  return !((ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) && p.expression === call);
}

export function flattenChain(terminal: ts.CallExpression): Chain {
  const links: Link[] = [];
  let cur: ts.Node = terminal;
  let rootName = "";
  for (let guard = 0; guard < 64; guard++) {
    cur = unwrap(cur);
    if (ts.isCallExpression(cur)) {
      const callee = unwrap(cur.expression);
      if (ts.isPropertyAccessExpression(callee)) {
        links.push({ name: callee.name.text, args: cur.arguments });
        cur = callee.expression;
      } else if (ts.isIdentifier(callee)) {
        rootName = callee.text;
        break;
      } else if (ts.isCallExpression(callee)) {
        cur = callee;
      } else break;
    } else if (ts.isPropertyAccessExpression(cur)) {
      links.push({ name: cur.name.text, args: [] });
      cur = cur.expression;
    } else if (ts.isIdentifier(cur)) {
      rootName = cur.text;
      break;
    } else break;
  }
  return { terminal, rootName, links: links.reverse() };
}

export function stringValue(expr: ts.Node | undefined): string | null {
  if (!expr) return null;
  const e = unwrap(expr);
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return e.text;
  return null;
}

function classify(chain: Chain, roots: RegExp): DataOp | null {
  const { links, rootName, terminal } = chain;
  if (links.length === 0 || NOT_A_DATABASE.test(rootName)) return null;

  if (/stripe/i.test(rootName)) {
    const method = links[links.length - 1]!.name;
    const resource = links[0]!.name;
    if (resource === "webhooks" || links.length < 2) return null;
    if (STRIPE_WRITES[method] === true) return { kind: "write", node: terminal, chain, via: "stripe", target: resource, method };
    if (STRIPE_READS[method] === true) return { kind: "read", node: terminal, chain, via: "stripe", target: resource, method };
    return null;
  }

  const fromIdx = links.findIndex((l) => l.name === "from" && stringValue(l.args[0]) !== null);
  const rootMatches = roots.test(rootName);
  if (!rootMatches && fromIdx === -1) return null;

  let write: Link | undefined;
  let read: Link | undefined;
  for (const l of links) {
    if (WRITE_METHODS[l.name] === true && !write) write = l;
    else if (READ_METHODS[l.name] === true && !read) read = l;
    else if (l.name === "rpc" && !write && !read) {
      if (RPC_WRITE.test(stringValue(l.args[0]) ?? "")) write = l;
      else read = l;
    }
  }
  const hit = write ?? read;
  if (!hit) return null;
  let target = "";
  if (fromIdx !== -1) target = stringValue(links[fromIdx]!.args[0]) ?? "";
  else if (rootMatches && /^prisma/i.test(rootName) && links[0] !== hit) target = links[0]!.name;
  return { kind: write ? "write" : "read", node: terminal, chain, via: "db", target, method: hit.name };
}

/** Data operations (database and Stripe calls) found anywhere under `root`, in source order. */
export function findDataOps(root: ts.Node, extraRoots: readonly string[] = []): DataOp[] {
  const extra = extraRoots.map((r) => r.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const roots = new RegExp(`^(?:${[ROOT_NAMES, ...extra].join("|")})$`, "i");
  const ops: DataOp[] = [];
  const visit = (n: ts.Node): void => {
    tick();
    if (ts.isCallExpression(n) && isChainTerminal(n)) {
      const op = classify(flattenChain(n), roots);
      if (op) ops.push(op);
    } else if (ts.isTaggedTemplateExpression(n) && ts.isIdentifier(n.tag) && roots.test(n.tag.text)) {
      const text = ts.isNoSubstitutionTemplateLiteral(n.template) ? n.template.text : n.template.head.text;
      const kind: OpKind = /^\s*(?:insert|update|delete|upsert|merge|truncate|alter|drop)\b/i.test(text) ? "write" : "read";
      ops.push({ kind, node: n, chain: { terminal: n, rootName: n.tag.text, links: [] }, via: "db", target: "", method: "sql" });
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return ops;
}

export interface Filter {
  column: string;
  value: ts.Expression;
}

function objectFilters(obj: ts.ObjectLiteralExpression, out: Filter[]): void {
  for (const p of obj.properties) {
    if (ts.isShorthandPropertyAssignment(p)) out.push({ column: p.name.text, value: p.name });
    else if (ts.isPropertyAssignment(p)) {
      const key = ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) ? p.name.text : null;
      if (key === null) continue;
      const init = unwrap(p.initializer);
      if ((key === "AND" || key === "OR") && ts.isArrayLiteralExpression(init)) {
        for (const el of init.elements) if (ts.isObjectLiteralExpression(el)) objectFilters(el, out);
      } else out.push({ column: key, value: p.initializer });
    }
  }
}

function drizzleFilters(expr: ts.Node, out: Filter[]): void {
  const e = unwrap(expr);
  if (!ts.isCallExpression(e)) return;
  const name = ts.isIdentifier(e.expression) ? e.expression.text : "";
  if (name === "and" || name === "or") {
    for (const a of e.arguments) drizzleFilters(a, out);
  } else if (/^(?:eq|ne|inArray|like|ilike|gt|gte|lt|lte)$/.test(name) && e.arguments.length >= 2) {
    const col = unwrap(e.arguments[0]!);
    const column = ts.isPropertyAccessExpression(col) ? col.name.text : (stringValue(col) ?? "");
    if (column) out.push({ column, value: e.arguments[1]! });
  }
}

/** Conditions that narrow which rows a query touches. */
export function extractFilters(chain: Chain): Filter[] {
  const out: Filter[] = [];
  for (const l of chain.links) {
    if (/^(?:eq|neq|gt|gte|lt|lte|like|ilike|is|in|contains)$/.test(l.name)) {
      const col = stringValue(l.args[0]);
      if (col !== null && l.args[1]) out.push({ column: col, value: l.args[1] });
    } else if (l.name === "filter") {
      const col = stringValue(l.args[0]);
      if (col !== null && l.args[2]) out.push({ column: col, value: l.args[2] });
    } else if (l.name === "match") {
      const arg = l.args[0] && unwrap(l.args[0]);
      if (arg && ts.isObjectLiteralExpression(arg)) objectFilters(arg, out);
    } else if (l.name === "where") {
      for (const a of l.args) {
        const u = unwrap(a);
        if (ts.isObjectLiteralExpression(u)) objectFilters(u, out);
        else drizzleFilters(u, out);
      }
    }
    // prisma-style `{ where: { ... } }` arguments
    for (const a of l.args) {
      const u = unwrap(a);
      if (!ts.isObjectLiteralExpression(u)) continue;
      for (const p of u.properties) {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === "where") {
          const w = unwrap(p.initializer);
          if (ts.isObjectLiteralExpression(w)) objectFilters(w, out);
        }
      }
    }
  }
  return out;
}

/** Column/value pairs written by insert, update, upsert and create calls. */
export function extractWrites(chain: Chain): Filter[] {
  const out: Filter[] = [];
  const fromObject = (obj: ts.ObjectLiteralExpression): void => {
    for (const p of obj.properties) {
      if (ts.isShorthandPropertyAssignment(p)) out.push({ column: p.name.text, value: p.name });
      else if (ts.isPropertyAssignment(p)) {
        const key = ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) ? p.name.text : null;
        if (key === null) continue;
        const init = unwrap(p.initializer);
        if (key === "data" && ts.isObjectLiteralExpression(init)) fromObject(init);
        else out.push({ column: key, value: p.initializer });
      }
    }
  };
  for (const l of chain.links) {
    if (!/^(?:insert|update|upsert|create|createMany|updateMany)$/.test(l.name)) continue;
    for (const a of l.args) {
      const u = unwrap(a);
      if (ts.isObjectLiteralExpression(u)) fromObject(u);
      else if (ts.isArrayLiteralExpression(u)) for (const el of u.elements) if (ts.isObjectLiteralExpression(unwrap(el))) fromObject(unwrap(el) as ts.ObjectLiteralExpression);
    }
  }
  return out;
}

/** Lower-case, alphanumerics only: `user_id`, `userId` and `UserID` all become `userid`. */
export function normalizeColumn(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}
