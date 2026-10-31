import ts from "typescript";
import { GitIgnore } from "../gitignore.js";
import { isEnvFile } from "../project.js";
import { lineOf, lineText, type SourceInfo } from "../ts/source.js";
import type { RawFinding, Severity } from "../types.js";
import { textLine, type Rule } from "./context.js";

/** Names whose value must never reach a browser. */
const SECRET_NAME = /(?:SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|DATABASE_URL|DB_URL|CONNECTION_STRING|WEBHOOK)/i;
/** Narrower list for NEXT_PUBLIC_ names, where tokens and keys are often public by design. */
const PUBLIC_LEAK_NAME = /^NEXT_PUBLIC_.*(?:SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|WEBHOOK|ADMIN_(?:KEY|TOKEN))/;
const BINDING_SECRET_NAME = /(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|auth[_-]?key|credential)/i;
const TEMPLATE_ENV = /^\.env(?:\.[A-Za-z0-9_-]+)*\.(?:example|sample|template|dist|defaults)$/;
const PLACEHOLDER = /(?:^$|^<|^\[|^\$\{|your[-_ ]|replace|example|placeholder|change[-_ ]?me|xxxx|todo|dummy|\.\.\.|^\*+$)/i;

export interface KeyShape {
  id: string;
  label: string;
  severity: Severity;
  pattern: RegExp;
}

/** Well-known credential shapes. Patterns are assembled from parts so this file holds no key-like literal. */
export const KEY_SHAPES: readonly KeyShape[] = [
  { id: "stripe-live", label: "Stripe live secret key", severity: "critical", pattern: new RegExp("\\b(?:sk|rk)" + "_live_[0-9A-Za-z]{16,}") },
  { id: "stripe-test", label: "Stripe test secret key", severity: "medium", pattern: new RegExp("\\b(?:sk|rk)" + "_test_[0-9A-Za-z]{16,}") },
  { id: "stripe-webhook", label: "Stripe webhook signing secret", severity: "high", pattern: new RegExp("\\bwh" + "sec_[0-9A-Za-z+/=]{16,}") },
  { id: "aws-access-key", label: "AWS access key id", severity: "critical", pattern: new RegExp("\\b(?:AK|AS)" + "IA[0-9A-Z]{16}\\b") },
  { id: "github-token", label: "GitHub token", severity: "critical", pattern: new RegExp("\\bgh[pousr]" + "_[0-9A-Za-z]{36,}\\b") },
  { id: "github-pat", label: "GitHub fine-grained token", severity: "critical", pattern: new RegExp("\\bgithub" + "_pat_[0-9A-Za-z_]{40,}") },
  { id: "slack-token", label: "Slack token", severity: "high", pattern: new RegExp("\\bxox[abprs]" + "-[0-9A-Za-z-]{10,}") },
  { id: "google-api-key", label: "Google API key (public if it is a Firebase web key)", severity: "medium", pattern: new RegExp("\\bAI" + "za[0-9A-Za-z_-]{35}\\b") },
  { id: "private-key", label: "Private key block", severity: "critical", pattern: new RegExp("-----BEGIN (?:[A-Z]+ )?PRIV" + "ATE KEY-----") },
  { id: "sk-key", label: "Secret key with an sk- prefix", severity: "high", pattern: new RegExp("\\bsk" + "-[A-Za-z0-9_-]{20,}") },
  { id: "postgres-url", label: "Database URL with an embedded password", severity: "high", pattern: /\bpostgres(?:ql)?:\/\/[^:/\s@]+:([^@\s]{4,})@/ },
  { id: "jwt", label: "JWT", severity: "critical", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}/ },
];

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function redact(secret: string): string {
  return `${secret.slice(0, 4)}…[${secret.length} chars]`;
}

interface Hit {
  label: string;
  severity: Severity;
  secret: string;
}

/** Matches a string value against the known shapes. Returns null for placeholders and public JWTs. */
export function detectKeyShape(value: string): Hit | null {
  for (const shape of KEY_SHAPES) {
    const m = shape.pattern.exec(value);
    if (!m) continue;
    const secret = m[0];
    if (shape.id === "jwt") {
      try {
        const payload: unknown = JSON.parse(Buffer.from(m[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
        if (typeof payload === "object" && payload !== null && "role" in payload && payload.role === "service_role") {
          return { label: "Supabase service-role JWT", severity: "critical", secret };
        }
      } catch {
        // not a JSON payload: not a token this rule understands
      }
      return null;
    }
    if (shape.id === "postgres-url") {
      const password = m[1]!;
      if (PLACEHOLDER.test(password) || /^(?:password|postgres|pass|secret)$/i.test(password)) return null;
      return { label: shape.label, severity: shape.severity, secret: password };
    }
    if (shape.id !== "private-key" && new Set(secret.slice(-12)).size < 4) continue;
    return { label: shape.label, severity: shape.severity, secret };
  }
  return null;
}

/** High-entropy value assigned to a secret-looking name. */
function looksLikeGenericSecret(name: string, value: string): boolean {
  if (!BINDING_SECRET_NAME.test(name)) return false;
  if (value.length < 16 || value.length > 200 || /\s/.test(value) || PLACEHOLDER.test(value)) return false;
  if (/^(?:https?:|\.{0,2}\/|process\.env)/.test(value) || value.includes("://")) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return false;
  return shannonEntropy(value) >= 3.5;
}

function bindingName(node: ts.Node): string | null {
  const p = node.parent;
  if (ts.isVariableDeclaration(p) && p.initializer === node && ts.isIdentifier(p.name)) return p.name.text;
  if (ts.isPropertyAssignment(p) && p.initializer === node) {
    if (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) return p.name.text;
  }
  if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.right === node) {
    if (ts.isIdentifier(p.left)) return p.left.text;
    if (ts.isPropertyAccessExpression(p.left)) return p.left.name.text;
  }
  return null;
}

interface EnvRef {
  name: string;
  node: ts.Node;
}

function isProcessEnv(e: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(e)) {
    if (ts.isIdentifier(e.expression) && e.expression.text === "process" && e.name.text === "env") return true;
    return ts.isMetaProperty(e.expression) && e.name.text === "env";
  }
  return false;
}

/** `process.env.X`, `process.env["X"]`, `import.meta.env.X` and `const { X } = process.env`. */
function envReferences(sf: ts.SourceFile): EnvRef[] {
  const refs: EnvRef[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n) && isProcessEnv(n.expression)) refs.push({ name: n.name.text, node: n });
    else if (ts.isElementAccessExpression(n) && ts.isPropertyAccessExpression(n.expression) && isProcessEnv(n.expression) && ts.isStringLiteralLike(n.argumentExpression)) {
      refs.push({ name: n.argumentExpression.text, node: n });
    } else if (ts.isVariableDeclaration(n) && n.initializer && ts.isPropertyAccessExpression(n.initializer) && isProcessEnv(n.initializer) && ts.isObjectBindingPattern(n.name)) {
      for (const el of n.name.elements) {
        const key = el.propertyName && (ts.isIdentifier(el.propertyName) || ts.isStringLiteral(el.propertyName)) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : null;
        if (key) refs.push({ name: key, node: el });
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return refs;
}

function publicLeak(file: string, line: number, name: string, evidence: string, where: string): RawFinding {
  return {
    rule: "secret-in-client",
    severity: "critical",
    file,
    line,
    title: `${name} publishes a secret to the browser`,
    message: `Next.js inlines every NEXT_PUBLIC_ variable into the client bundle at build time (${where}). A name containing a secret marker means the value is readable by every visitor.`,
    evidence,
    fix: "Rename the variable without the NEXT_PUBLIC_ prefix, read it only in route handlers or server components, and rotate the key because it has already been exposed.",
  };
}

function scanSource(src: SourceInfo, out: RawFinding[], seen: Set<string>): void {
  const { sf, path } = src;

  // 1. NEXT_PUBLIC_ names that should not be public
  const visitNames = (n: ts.Node): void => {
    let text: string | null = null;
    if (ts.isIdentifier(n)) text = n.text;
    else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) text = n.text;
    if (text !== null && PUBLIC_LEAK_NAME.test(text) && /^NEXT_PUBLIC_[A-Z0-9_]+$/.test(text)) {
      const line = lineOf(sf, n);
      const key = `${path}:${line}:${text}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(publicLeak(path, line, text, lineText(sf, line), "source reference"));
      }
    }
    ts.forEachChild(n, visitNames);
  };
  visitNames(sf);

  // 2. server secrets read from client components
  if (src.isClient) {
    for (const ref of envReferences(sf)) {
      if (ref.name.startsWith("NEXT_PUBLIC_") || !SECRET_NAME.test(ref.name)) continue;
      const line = lineOf(sf, ref.node);
      out.push({
        rule: "secret-in-client",
        severity: "high",
        file: path,
        line,
        title: `Client component reads server secret ${ref.name}`,
        message: `This file starts with "use client", so it is bundled for the browser. Non-public environment variables are not available there; code that needs ${ref.name} in the browser is either broken or one rename away from publishing it as NEXT_PUBLIC_.`,
        evidence: lineText(sf, line),
        fix: "Move the call that needs the secret into a route handler, server action or server component and call that from the client component.",
      });
    }
  }

  // 3. next.config env block inlines values into the client bundle
  if (/(?:^|\/)next\.config\.[cm]?[jt]s$/.test(path)) {
    const visit = (n: ts.Node): void => {
      if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === "env" && ts.isObjectLiteralExpression(n.initializer)) {
        for (const p of n.initializer.properties) {
          if (!ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p)) continue;
          const key = ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) ? p.name.text : "";
          if (!SECRET_NAME.test(key)) continue;
          const line = lineOf(sf, p);
          out.push(publicLeak(path, line, key, lineText(sf, line), "next.config env block"));
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }

  // 4. key-shaped and high-entropy literals
  const visitLiterals = (n: ts.Node): void => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      const value = n.text;
      if (value.length >= 16) {
        const line = lineOf(sf, n);
        const hit = detectKeyShape(value);
        if (hit) {
          out.push(hardcoded(path, line, hit.label, hit.severity, lineText(sf, line).replace(hit.secret, redact(hit.secret))));
        } else {
          const name = bindingName(n);
          if (name && looksLikeGenericSecret(name, value)) {
            out.push(hardcoded(path, line, `High-entropy string assigned to ${name}`, "medium", lineText(sf, line).replace(value, redact(value))));
          }
        }
      }
    }
    ts.forEachChild(n, visitLiterals);
  };
  visitLiterals(sf);
}

function hardcoded(file: string, line: number, label: string, severity: Severity, evidence: string): RawFinding {
  return {
    rule: "secret-hardcoded",
    severity,
    file,
    line,
    title: `Hard-coded secret: ${label}`,
    message: "Secrets in source end up in git history, build logs and every clone. Removing the line does not remove the value from history.",
    evidence,
    fix: "Rotate the credential, load the new one from an environment variable or a secret manager, and add the variable name to .env.example without a value.",
  };
}

interface EnvLine {
  key: string;
  value: string;
  line: number;
}

function parseEnv(text: string): EnvLine[] {
  const out: EnvLine[] = [];
  text.split(/\r?\n/).forEach((raw, idx) => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(raw);
    if (!m) return;
    let value = m[2]!;
    const quoted = /^(["'])(.*)\1/.exec(value);
    if (quoted) value = quoted[2]!;
    else value = value.replace(/\s+#.*$/, "");
    out.push({ key: m[1]!, value, line: idx + 1 });
  });
  return out;
}

function scanEnvFiles(files: ReadonlyMap<string, string>, tracked: ReadonlySet<string> | null, out: RawFinding[]): void {
  const ignore = new GitIgnore(files);
  const hasGitignore = [...files.keys()].some((p) => p === ".gitignore" || p.endsWith("/.gitignore"));
  for (const [path, text] of files) {
    const name = path.slice(path.lastIndexOf("/") + 1);
    if (!isEnvFile(name)) continue;
    const isTemplate = TEMPLATE_ENV.test(name);
    const lines = parseEnv(text);

    for (const l of lines) {
      if (PUBLIC_LEAK_NAME.test(l.key)) out.push(publicLeak(path, l.line, l.key, `${l.key}=…`, "env file"));
      if (isTemplate && l.value !== "") {
        const hit = detectKeyShape(l.value);
        if (hit) out.push(hardcoded(path, l.line, hit.label, hit.severity, `${l.key}=${redact(hit.secret)}`));
        else if (looksLikeGenericSecret(l.key, l.value)) out.push(hardcoded(path, l.line, `High-entropy value for ${l.key}`, "medium", `${l.key}=${redact(l.value)}`));
      }
    }
    if (isTemplate) continue;

    const isTracked = tracked ? tracked.has(path) : null;
    const ignored = ignore.isIgnored(path);
    const exposed = isTracked === null ? !ignored : isTracked || !ignored;
    if (!exposed) continue;
    const secretKeys = lines.filter((l) => SECRET_NAME.test(l.key) && !PLACEHOLDER.test(l.value));
    const first = lines[0]?.line ?? 1;
    let severity: Severity;
    if (isTracked) severity = secretKeys.length > 0 ? "critical" : "high";
    else severity = secretKeys.length > 0 ? "high" : "medium";
    const state = isTracked ? "tracked by git" : `not ignored by ${hasGitignore ? ".gitignore" : "git (the project has no .gitignore)"}`;
    out.push({
      rule: "secret-committed-env",
      severity,
      file: path,
      line: first,
      title: `${path} is ${state}`,
      message: `Environment files hold credentials. ${isTracked ? "A tracked file is in every clone and in history even if it is deleted later." : "The next `git add .` will commit it."}${secretKeys.length > 0 ? ` It defines ${secretKeys.map((k) => k.key).join(", ")}.` : " It currently holds only empty or placeholder secret values."}`,
      evidence: secretKeys.length > 0 ? `${secretKeys[0]!.key}=…` : textLine(text, first).replace(/=.*/, "=…"),
      fix: isTracked
        ? `Run "git rm --cached ${path}", add ".env*" (and "!.env.example") to .gitignore, rotate every credential the file ever held, and keep a value-free .env.example.`
        : `Add ".env*" (and "!.env.example") to .gitignore before the first commit that includes ${path}.`,
    });
  }
}

export const secretRules: Rule = (ctx) => {
  const out: RawFinding[] = [];
  const seen = new Set<string>();
  for (const src of ctx.sources) scanSource(src, out, seen);
  scanEnvFiles(ctx.project.files, ctx.project.gitTracked, out);
  return out;
};
