import ts from "typescript";
import { shellQuote } from "../shell.js";
import { entryLabel, entrySite, findAll, lineOf, lineText, unwrap, type SourceInfo } from "../ts/source.js";
import type { RawFinding, Site } from "../types.js";
import { textLine, type AuditContext, type Rule } from "./context.js";
import { isStripeWebhook } from "./stripe.js";

const ACAO = "access-control-allow-origin";
const ACAC = "access-control-allow-credentials";
const SECURITY_HEADERS = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy", "permissions-policy"];
const RATE_LIMIT_HINT = /rate[-_ ]?limit|ratelimit|throttle|limiter/i;
const SENSITIVE_ROUTE = /(?:^|[/._-])(?:auth|login|signin|sign-in|signup|sign-up|register|reset|password|otp|verify|magic|token|webhooks?|callback|invite)(?:[/._-]|$)/i;

function isTrueLiteral(e: ts.Node | undefined): boolean {
  if (!e) return false;
  const u = unwrap(e);
  return u.kind === ts.SyntaxKind.TrueKeyword || ((ts.isStringLiteral(u) || ts.isNoSubstitutionTemplateLiteral(u)) && u.text.toLowerCase() === "true");
}

type OriginKind = "wildcard" | "reflected" | null;

function originKind(value: ts.Node | undefined): OriginKind {
  if (!value) return null;
  const u = unwrap(value);
  if (ts.isStringLiteral(u) || ts.isNoSubstitutionTemplateLiteral(u)) return u.text.trim() === "*" ? "wildcard" : null;
  if (u.kind === ts.SyntaxKind.TrueKeyword) return "reflected";
  const mentionsOrigin = findAll(u, (n): n is ts.Identifier | ts.StringLiteral => ts.isIdentifier(n) || ts.isStringLiteral(n)).some((n) => /origin/i.test(n.text));
  return mentionsOrigin ? "reflected" : null;
}

function enclosingScope(node: ts.Node): ts.Node {
  let n: ts.Node | undefined = node.parent;
  while (n && !ts.isFunctionLike(n) && !ts.isSourceFile(n)) n = n.parent;
  return n ?? node;
}

interface HeaderSite {
  node: ts.Node;
  scope: ts.Node;
  value: ts.Node | undefined;
}

/** Finds places that set the given response header: object keys, { key, value } pairs and set/append calls. */
function headerSites(sf: ts.SourceFile, header: string): HeaderSite[] {
  const sites: HeaderSite[] = [];
  const visit = (n: ts.Node): void => {
    if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && n.text.toLowerCase() === header) {
      const p = n.parent;
      if (ts.isPropertyAssignment(p) && p.name === n) sites.push({ node: n, scope: enclosingScope(n), value: p.initializer });
      else if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === "key" && ts.isObjectLiteralExpression(p.parent)) {
        const valueProp = p.parent.properties.find((q): q is ts.PropertyAssignment => ts.isPropertyAssignment(q) && ts.isIdentifier(q.name) && q.name.text === "value");
        sites.push({ node: n, scope: enclosingScope(n), value: valueProp?.initializer });
      } else if (ts.isCallExpression(p) && p.arguments[0] === n && ts.isPropertyAccessExpression(p.expression) && /^(?:set|setHeader|append|header)$/.test(p.expression.name.text)) {
        sites.push({ node: n, scope: enclosingScope(n), value: p.arguments[1] });
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return sites;
}

function corsFindings(src: SourceInfo, out: RawFinding[]): void {
  const { sf, path } = src;
  const report = (node: ts.Node, kind: "wildcard" | "reflected"): void => {
    const line = lineOf(sf, node);
    out.push({
      rule: "cors-wildcard-credentials",
      severity: "high",
      file: path,
      line,
      title: kind === "wildcard" ? "CORS allows every origin together with credentials" : "CORS reflects the request origin together with credentials",
      message:
        kind === "wildcard"
          ? 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is the configuration browsers reject, and it is usually "fixed" by reflecting the Origin header, which is worse.'
          : "Echoing the Origin header back with credentials allowed lets any website make authenticated requests to this API in the visitor's browser and read the response.",
      evidence: lineText(sf, line),
      fix: "Keep an explicit list of allowed origins, compare the Origin header against it, and only then set Access-Control-Allow-Origin to that exact value. Never combine a wildcard with credentials.",
    });
  };

  const credentials = headerSites(sf, ACAC).filter((s) => isTrueLiteral(s.value));
  for (const site of headerSites(sf, ACAO)) {
    const kind = originKind(site.value);
    if (!kind) continue;
    // same function, or one scope nested in the other (a file-level object next to a handler)
    const nested = (a: ts.Node, b: ts.Node): boolean => a.pos <= b.pos && a.end >= b.end;
    if (credentials.some((c) => nested(c.scope, site.scope) || nested(site.scope, c.scope))) report(site.node, kind);
  }

  // cors({ origin, credentials }) from the cors package
  for (const call of findAll(sf, (n): n is ts.CallExpression => ts.isCallExpression(n))) {
    if (!(ts.isIdentifier(call.expression) && /^cors$/i.test(call.expression.text))) continue;
    const opts = call.arguments[0] && unwrap(call.arguments[0]);
    if (!opts || !ts.isObjectLiteralExpression(opts)) continue;
    const prop = (name: string): ts.Expression | undefined => opts.properties.find((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === name)?.initializer;
    const kind = originKind(prop("origin"));
    if (kind && isTrueLiteral(prop("credentials"))) report(opts, kind);
  }
}

function nextConfigFindings(src: SourceInfo, out: RawFinding[]): void {
  const { sf, path } = src;
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && /^(?:ignoreBuildErrors|ignoreDuringBuilds)$/.test(n.name.text) && isTrueLiteral(n.initializer)) {
      const line = lineOf(sf, n);
      const typeCheck = n.name.text === "ignoreBuildErrors";
      out.push({
        rule: "build-checks-disabled",
        severity: "medium",
        file: path,
        line,
        title: typeCheck ? "next build ignores TypeScript errors" : "next build skips ESLint",
        message: `${typeCheck ? "Type errors" : "Lint errors"} ship to production unnoticed. Generated code that does not compile often contains exactly the wrong-argument and missing-await mistakes that cause security and billing bugs, and this switch hides them.`,
        evidence: lineText(sf, line),
        fix: `Remove the flag and fix the ${typeCheck ? "type errors (npx tsc --noEmit lists them)" : "lint errors"}. Run the check in CI so it cannot regress.`,
      });
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);

  // weakened headers
  for (const lit of findAll(sf, (n): n is ts.StringLiteral => ts.isStringLiteral(n))) {
    const line = lineOf(sf, lit);
    if (/^allowall$/i.test(lit.text) || (/script-src[^;]*\*/.test(lit.text) && !/script-src[^;]*\*\./.test(lit.text)) || /unsafe-eval/.test(lit.text)) {
      out.push({
        rule: "security-headers",
        severity: "low",
        file: path,
        line,
        title: "Weakened security header",
        message: "A header value permits framing from anywhere, wildcard script sources or eval, which removes most of what the header is for.",
        evidence: lineText(sf, line),
        fix: "Use X-Frame-Options: DENY (or frame-ancestors in the CSP), list script sources explicitly, and drop unsafe-eval; use a nonce-based CSP for inline scripts.",
      });
    }
  }
}

function rateLimitFindings(ctx: AuditContext, out: RawFinding[]): void {
  const middleware = ctx.sources.filter((s) => /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(s.path));
  if (middleware.some((s) => RATE_LIMIT_HINT.test(s.text))) return;
  const custom = ctx.config.rateLimiters;
  for (const src of ctx.sources) {
    if (src.isClient || src.entries.length === 0) continue;
    const entries = src.entries.filter((e) => e.kind !== "page");
    const first = entries[0];
    if (!first) continue;
    if (!SENSITIVE_ROUTE.test(src.path) && !isStripeWebhook(src)) continue;
    if (RATE_LIMIT_HINT.test(src.text) || custom.some((name) => src.text.includes(name))) continue;
    const line = lineOf(src.sf, first.decl);
    out.push({
      rule: "no-rate-limit",
      severity: "info",
      file: src.path,
      line,
      title: "No rate limiting recognised on an auth or webhook route",
      message: "Login, password reset, token and webhook endpoints are brute-force and cost-amplification targets. No rate limiter, throttle or middleware limiter was found in this file or in the middleware. Informational: the platform in front of the app may already provide one.",
      evidence: lineText(src.sf, line),
      fix: "Add a limiter keyed by IP and by account (for example a sliding window in Redis) to credential and email-sending routes. Webhooks can be limited by source IP range or left to the platform.",
      subject: [entryLabel(first)],
      entry: entrySite(src, first),
    });
  }
}

/** Line of the object a next.config file exports (`export default x`, `module.exports = x`), or null when it cannot be found. */
function exportedConfigLine(sf: ts.SourceFile): number | null {
  const declared = (name: string): ts.Node | null => {
    for (const stmt of sf.statements) {
      if (!ts.isVariableStatement(stmt)) continue;
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) return d;
    }
    return null;
  };
  for (const stmt of sf.statements) {
    let exported: ts.Node | null = null;
    if (ts.isExportAssignment(stmt)) exported = stmt.expression;
    else if (ts.isExpressionStatement(stmt) && ts.isBinaryExpression(stmt.expression) && stmt.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken && /^module\.exports$/.test(stmt.expression.left.getText(sf))) exported = stmt.expression.right;
    if (!exported) continue;
    const value = unwrap(exported);
    return lineOf(sf, (ts.isIdentifier(value) ? declared(value.text) : null) ?? stmt);
  }
  return null;
}

function securityHeaderFindings(ctx: AuditContext, out: RawFinding[]): void {
  const config = ctx.sources.find((s) => /(?:^|\/)next\.config\.[cm]?[jt]s$/.test(s.path));
  const pkg = ctx.project.files.get("package.json");
  if (!config && !(pkg && /"next"\s*:/.test(pkg))) return;
  const configured = ctx.sources.some((s) => findAll(s.sf, (n): n is ts.StringLiteral => ts.isStringLiteral(n)).some((l) => SECURITY_HEADERS.includes(l.text.toLowerCase())));
  if (configured) return;
  const file = config?.path ?? "package.json";
  const line = config ? 1 : (pkg!.split(/\r?\n/).findIndex((l) => /"next"\s*:/.test(l)) + 1 || 1);
  const configLine = config ? exportedConfigLine(config.sf) : null;
  const configSite: Site | null = config && configLine !== null && configLine !== line
    ? { file, line: configLine, note: "next.config is where a headers() function would set the missing headers", text: lineText(config.sf, configLine) }
    : null;
  out.push({
    rule: "security-headers",
    severity: "info",
    file,
    line,
    title: "No security headers are configured",
    message: "No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security or Referrer-Policy header is set in next.config or anywhere in the source. The hosting platform may add some; Next.js adds none by default.",
    evidence: config ? textLine(config.text, 1) : textLine(pkg!, line),
    fix: 'Return the headers from an async headers() function in next.config for source "/(.*)": X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy strict-origin-when-cross-origin, Strict-Transport-Security, and a Content-Security-Policy suited to the app.',
    ...(configSite ? { sink: configSite } : {}),
  });
}

const WILDCARD_SPEC = /^(?:\*|latest|x|)$/i;

function packageFindings(ctx: AuditContext, out: RawFinding[]): void {
  for (const [path, text] of ctx.project.files) {
    if (path !== "package.json" && !path.endsWith("/package.json")) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    const lines = text.split(/\r?\n/);
    const keyLine = new Map<string, number>();
    lines.forEach((l, i) => {
      const raw = /^\s*"((?:[^"\\]|\\.){1,214})"\s*:/.exec(l)?.[1];
      if (raw === undefined) return;
      let key = raw;
      if (raw.includes("\\")) {
        try {
          key = String(JSON.parse(`"${raw}"`));
        } catch {
          return;
        }
      }
      if (!keyLine.has(key)) keyLine.set(key, i + 1);
    });
    let hasDeps = false;
    for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const deps: unknown = section in parsed ? Reflect.get(parsed, section) : undefined;
      if (typeof deps !== "object" || deps === null) continue;
      for (const [name, spec] of Object.entries(deps)) {
        hasDeps = true;
        if (typeof spec !== "string" || !WILDCARD_SPEC.test(spec.trim())) continue;
        const line = keyLine.get(name) ?? keyLine.get(section) ?? 1;
        out.push({
          rule: "deps-unpinned",
          severity: "low",
          file: path,
          line,
          title: `${name} is declared as "${spec}"`,
          message: "Every install can resolve to a different major version, including one published minutes ago. Builds stop being reproducible and a compromised release is picked up automatically.",
          evidence: textLine(text, line),
          fix: `Pin ${name} to the version in use (npm install ${shellQuote(`${name}@<version>`)} --save-exact) and commit the lockfile.`,
          subject: [name],
        });
      }
    }
    if (path === "package.json" && hasDeps) {
      const lock = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"].some((l) => ctx.project.paths.has(l));
      if (!lock) {
        const declLine = Math.min(...["dependencies", "devDependencies", "optionalDependencies"].map((k) => keyLine.get(k) ?? Infinity), Infinity);
        out.push({
          rule: "deps-unpinned",
          severity: "low",
          file: path,
          line: 1,
          title: "No lockfile",
          message: "Without a lockfile transitive dependencies are resolved fresh on every install, so a build today and a build tomorrow can differ.",
          evidence: textLine(text, 1),
          fix: "Commit package-lock.json (or the lockfile of your package manager) and install with npm ci in CI.",
          subject: ["no lockfile"],
          ...(Number.isFinite(declLine) && declLine > 1 ? { sink: { file: path, line: declLine, note: "Dependencies are declared here and no lockfile exists next to this file", text: textLine(text, declLine) } } : {}),
        });
      }
    }
  }
}

export const hygieneRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  for (const src of ctx.sources) {
    ctx.guard(src.path, () => {
      corsFindings(src, out);
      if (/(?:^|\/)next\.config\.[cm]?[jt]s$/.test(src.path)) nextConfigFindings(src, out);
    });
  }
  ctx.guard("package.json", () => packageFindings(ctx, out));
  ctx.guard("next.config", () => securityHeaderFindings(ctx, out));
  ctx.guard("route handlers", () => rateLimitFindings(ctx, out));
  return out;
};
