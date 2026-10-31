/**
 * Credential shapes, redaction and scrubbing. Everything that prints source text
 * (evidence lines, warnings) goes through `scrubSecrets`, so a secret that happens
 * to sit on a line another rule reports is not echoed into a report.
 */
import type { Severity } from "./types.js";

export interface KeyShape {
  id: string;
  label: string;
  severity: Severity;
  /** The first four characters are the vendor prefix, so they are safe to show. */
  showPrefix: boolean;
  pattern: RegExp;
}

/**
 * Well-known credential shapes. Patterns are assembled from parts so this file holds
 * no key-like literal. Quantifiers that could run on for the length of a string without
 * finding the closing part (database URL, JWT) are bounded, so matching is linear in
 * the length of the input.
 */
export const KEY_SHAPES: readonly KeyShape[] = [
  { id: "stripe-live", label: "Stripe live secret key", severity: "critical", showPrefix: true, pattern: new RegExp("\\b(?:sk|rk)" + "_live_[0-9A-Za-z]{16,}") },
  { id: "stripe-test", label: "Stripe test secret key", severity: "medium", showPrefix: true, pattern: new RegExp("\\b(?:sk|rk)" + "_test_[0-9A-Za-z]{16,}") },
  { id: "stripe-webhook", label: "Stripe webhook signing secret", severity: "high", showPrefix: true, pattern: new RegExp("\\bwh" + "sec_[0-9A-Za-z+/=]{16,}") },
  { id: "aws-access-key", label: "AWS access key id", severity: "critical", showPrefix: true, pattern: new RegExp("\\b(?:AK|AS)" + "IA[0-9A-Z]{16}\\b") },
  { id: "github-token", label: "GitHub token", severity: "critical", showPrefix: true, pattern: new RegExp("\\bgh[pousr]" + "_[0-9A-Za-z]{36,}\\b") },
  { id: "github-pat", label: "GitHub fine-grained token", severity: "critical", showPrefix: true, pattern: new RegExp("\\bgithub" + "_pat_[0-9A-Za-z_]{40,}") },
  { id: "slack-token", label: "Slack token", severity: "high", showPrefix: true, pattern: new RegExp("\\bxox[abprs]" + "-[0-9A-Za-z-]{10,}") },
  { id: "google-api-key", label: "Google API key (public if it is a Firebase web key)", severity: "medium", showPrefix: true, pattern: new RegExp("\\bAI" + "za[0-9A-Za-z_-]{35}\\b") },
  { id: "private-key", label: "Private key block", severity: "critical", showPrefix: false, pattern: new RegExp("-----BEGIN (?:[A-Z]+ )?PRIV" + "ATE KEY-----") },
  { id: "sk-key", label: "Secret key with an sk- prefix", severity: "high", showPrefix: true, pattern: new RegExp("\\bsk" + "-[A-Za-z0-9_-]{20,}") },
  { id: "postgres-url", label: "Database URL with an embedded password", severity: "high", showPrefix: false, pattern: /\bpostgres(?:ql)?:\/\/[^:/\s@]{1,128}:([^@\s]{4,256})@/ },
  { id: "jwt", label: "JWT", severity: "critical", showPrefix: false, pattern: /\beyJ[A-Za-z0-9_-]{8,200}\.(eyJ[A-Za-z0-9_-]{8,4096})\.[A-Za-z0-9_-]{8,1024}/ },
];

export function redact(secret: string, showPrefix = true): string {
  return showPrefix ? `${secret.slice(0, 4)}…[${secret.length} chars]` : `[${secret.length} chars]`;
}

const ESCAPES = /\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\})/g;

/** Decodes \xHH, \uHHHH and \u{H...} so an escaped secret can be recognised. */
export function decodeEscapes(text: string): string {
  return text.replace(ESCAPES, (_m, hex2: string | undefined, hex4: string | undefined, hexN: string | undefined) => {
    const code = Number.parseInt(hex2 ?? hex4 ?? hexN ?? "", 16);
    return code <= 0x10ffff ? String.fromCodePoint(code) : "";
  });
}

function matchesAnyShape(text: string): boolean {
  return KEY_SHAPES.some((s) => s.pattern.test(text));
}

const GLOBAL_SHAPES: readonly { shape: KeyShape; global: RegExp }[] = KEY_SHAPES.map((shape) => ({ shape, global: new RegExp(shape.pattern.source, "g") }));

/**
 * Replaces every credential-shaped substring of `text` with a redaction. A line in which
 * a secret is only visible after decoding escapes is withheld as a whole, because the
 * decoded position cannot be mapped back onto the source text.
 */
export function scrubSecrets(text: string): string {
  const decoded = decodeEscapes(text);
  if (decoded !== text && matchesAnyShape(decoded)) return "[line withheld: it contains an escaped secret]";
  let out = text;
  for (const { shape, global } of GLOBAL_SHAPES) {
    if (shape.id === "private-key") {
      out = out.replace(new RegExp(`${shape.pattern.source}[^]*`, "g"), () => "[private key withheld]");
    } else if (shape.id === "postgres-url") {
      out = out.replace(global, (match: string, password: string) => match.replace(password, () => "[password withheld]"));
    } else if (shape.id === "jwt") {
      out = out.replace(global, () => "[JWT withheld]");
    } else {
      out = out.replace(global, (match: string) => redact(match, shape.showPrefix));
    }
  }
  return out;
}

/** Longest prefix of a line that is scrubbed. Longer than the longest credential shape the patterns accept. */
export const SCRUB_WINDOW = 8192;

/** A source line as evidence: trimmed, scrubbed of credential-shaped substrings, then cut to `max` characters. */
export function evidenceLine(raw: string, max = 180): string {
  const scrubbed = scrubSecrets(raw.trim().slice(0, SCRUB_WINDOW));
  return scrubbed.length > max ? scrubbed.slice(0, max - 1) + "…" : scrubbed;
}
