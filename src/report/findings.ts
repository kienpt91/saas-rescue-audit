/**
 * Export in the findings.json shape that Cloudflare's open source security-audit-skill publishes
 * (https://github.com/cloudflare/security-audit-skill), so the output can be read by tools that expect it.
 * This project is not affiliated with Cloudflare. The shape is re-implemented here from its public
 * description; no code or schema file of that project is used.
 *
 * What the tool can honestly say about its results:
 *
 * - every finding is a static one, so it is exported as `needs_validation`, never as `confirmed`: nothing
 *   ran and nothing demonstrated it;
 * - a finding that the project itself silenced (inline comment, config) is exported as `rejected`, with
 *   a reason that says whose decision that was and that the tool did not test it.
 *
 * The record types below can only describe those two verdicts, so the encoder cannot produce another one.
 * Text that comes from the audited repository is made safe for a reader before it is written: control,
 * format, line-separator and default-ignorable characters and lone surrogates become visible escapes
 * (`\x1b`, `\u{202e}`). Backslashes are not escaped, so a source line that really contains the text `\x1b`
 * reads the same as one that contained the control character; the escapes are for the reader's safety,
 * not a reversible encoding.
 */
import { SEVERITY_RANK, type AuditResult, type Finding, type Site, type SuppressedFinding } from "../types.js";
import { FALLBACK_PLAN, RULE_PLANS, STATIC_ONLY_BLOCKER, type RulePlan } from "./findings-plans.js";

export interface TraceStep {
  kind: "entrypoint" | "sink";
  file: string;
  line: number;
  scope: string;
  description: string;
}

export interface EvidenceItem {
  file: string;
  line: number;
  description: string;
}

interface RecordBase {
  fingerprint: string;
  title: string;
  description: string;
  claimed_root_cause: string;
  trace: TraceStep[];
  evidence: EvidenceItem[];
}

export interface NeedsValidationRecord extends RecordBase {
  verdict: "needs_validation";
  blockers: string[];
  validation_plan: { local: string; deployment?: string };
}

export interface RejectedRecord extends RecordBase {
  verdict: "rejected";
  reason: string;
}

export type FindingRecord = NeedsValidationRecord | RejectedRecord;

/** Why a finding is not in the export. Counted, never silent: the command line prints it on stderr. */
export type OmissionReason = "path-not-representable" | "line-unknown" | "record-limit" | "size-limit";

export interface Omission {
  reason: OmissionReason;
  count: number;
}

export interface FindingsExport {
  records: FindingRecord[];
  omitted: Omission[];
  /** The array as JSON text, two-space indented, one trailing newline. */
  text: string;
}

/** The format reader's limits. A larger export would be refused, so the lowest-rated findings (by severity, silenced or not) are left out and counted. */
export const MAX_RECORDS = 1000;
export const MAX_BYTES = 5 * 1024 * 1024;

export const OMISSION_TEXT: Readonly<Record<OmissionReason, string>> = {
  "path-not-representable": "the file name cannot be written as a repository-relative path in this format (control characters, a colon, a backslash, a trailing dot or space, a reserved name)",
  "line-unknown": "the line number is not a positive integer",
  "record-limit": `beyond the ${MAX_RECORDS}-record limit of the format; findings were kept in order of severity until it was reached`,
  "size-limit": "beyond the 5 MiB size limit of the format; findings were kept in order of severity until the first one that did not fit",
};

// ---------------------------------------------------------------------------------------------
// text safety

const UNSAFE_CHAR = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const VISIBLE_CHAR = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;

function escapeChar(ch: string): string {
  const code = ch.codePointAt(0) ?? 0;
  return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u{${code.toString(16)}}`;
}

/** Repository text for a reader: unsafe characters become visible escapes. Newlines are kept only when `lines` is set. */
function safeText(text: string, lines = false): string {
  const escape = (s: string): string => s.replace(UNSAFE_CHAR, escapeChar);
  return lines ? text.split(/\r?\n/).map(escape).join("\n") : escape(text);
}

/** Safe text that is guaranteed to show at least one character; `fallback` is fixed text written by this tool. */
function prose(text: string, fallback: string, lines = false): string {
  const safe = safeText(text, lines);
  return VISIBLE_CHAR.test(safe) ? safe : fallback;
}

const RESERVED_NAME = /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|(?:com|lpt)[1-9\u00b9\u00b2\u00b3])(?:\.|$)/iu;
const PATH_UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\\:]/u;

/** A path the format accepts: relative, forward slashes, nothing a file system or a terminal treats specially. */
export function isRepositoryPath(path: string): boolean {
  if (path === "" || PATH_UNSAFE.test(path) || path !== path.trim() || path.startsWith("/") || path.startsWith("~")) return false;
  return path.split("/").every((part) => part !== "" && part !== "." && part !== ".." && !/[ .]$/.test(part) && !RESERVED_NAME.test(part));
}

// ---------------------------------------------------------------------------------------------
// fingerprint

const SEGMENT_KEEP = /[A-Za-z0-9._-]/;
const encoder = new TextEncoder();

/** UTF-8 bytes; letters, digits, `.`, `_` and `-` stay, every other byte becomes `+` and two lowercase hex digits. */
export function encodeSegment(text: string): string {
  let out = "";
  for (const byte of encoder.encode(text)) {
    const ch = String.fromCharCode(byte);
    out += byte < 0x80 && SEGMENT_KEEP.test(ch) ? ch : `+${byte.toString(16).padStart(2, "0")}`;
  }
  return out;
}

export function encodePath(path: string): string {
  return path.split("/").map(encodeSegment).join("/");
}

/**
 * `saas-audit/<rule>:<path>:<subject>[:<subject>...]`. Built from the rule, the file and the names the
 * rule recorded (table, policy, handler, variable), never from a line number or a time, so a change that
 * only moves code leaves it as it was. The proof-audit export builds the same identity for the same
 * finding, so a finding and its later database verdict carry one fingerprint.
 */
export function fingerprintBase(f: Pick<Finding, "rule" | "file" | "title" | "subject">): string {
  const names = (f.subject ?? []).filter((s) => s !== "");
  const subject = names.length > 0 ? names : [f.title];
  return `saas-audit/${encodeSegment(f.rule)}:${encodePath(f.file)}:${subject.map(encodeSegment).join(":")}`;
}

// ---------------------------------------------------------------------------------------------
// records

interface Candidate {
  finding: Finding;
  suppressedBy: string | null;
  order: number;
}

const positiveInt = (n: number): boolean => Number.isInteger(n) && n >= 1;

function usableSite(site: Site | undefined): Site | null {
  return site !== undefined && positiveInt(site.line) && isRepositoryPath(site.file) ? site : null;
}

function describeSource(text: string | undefined): string {
  const body = prose(text ?? "", "", true).trim();
  return `Source line: ${body === "" ? "(blank line)" : body}`;
}

function rejectionReason(suppressedBy: string): string {
  const by =
    suppressedBy === "inline comment"
      ? "a saas-audit-ignore comment in the project"
      : suppressedBy === "config ignoreRules"
        ? "the ignoreRules setting in the project's saas-audit config"
        : suppressedBy === "config publicRoutes"
          ? "the publicRoutes setting in the project's saas-audit config, which lists the route as public on purpose"
          : `the project's own settings (${prose(suppressedBy, "unnamed setting")})`;
  return `Not counted by saas-audit: ${by} silences this finding. That is the project's own decision that the behaviour is intended or accepted. saas-audit did not test or disprove the claim, and the record is kept so its fingerprint stays the same if the silencing is removed.`;
}

interface Built {
  record: FindingRecord;
  rank: number;
}

function build(c: Candidate, fingerprint: string): Built | Omission["reason"] {
  const f = c.finding;
  if (!positiveInt(f.line)) return "line-unknown";
  const plan: RulePlan = RULE_PLANS[f.rule] ?? FALLBACK_PLAN;
  const primary: Site = { file: f.file, line: f.line, note: plan.sink, text: f.evidence };
  if (!isRepositoryPath(primary.file)) return "path-not-representable";

  // the weak spot: the rule's own sink site when it recorded one, else the finding's file and line
  const sinkSite = usableSite(f.sink) ?? primary;
  const entrySite = usableSite(f.entry);
  const entry = entrySite !== null && !(entrySite.file === sinkSite.file && entrySite.line === sinkSite.line) ? entrySite : null;
  const sinkText = sinkSite === primary ? f.evidence : sinkSite.text;
  const scope = prose((f.subject ?? []).join(" / "), prose(f.title, f.rule));

  const trace: TraceStep[] = [];
  if (entry) trace.push({ kind: "entrypoint", file: entry.file, line: entry.line, scope, description: prose(entry.note, "Entry point") });
  const single = entry === null;
  const kind = single ? plan.single : "sink";
  const alone = single && kind === "entrypoint" && entrySite !== null ? entrySite.note : sinkSite.note;
  trace.push({ kind, file: sinkSite.file, line: sinkSite.line, scope, description: prose(alone, plan.sink) });

  const evidence: EvidenceItem[] = [{ file: sinkSite.file, line: sinkSite.line, description: describeSource(sinkText) }];
  if (entry !== null && entry.text !== undefined) evidence.push({ file: entry.file, line: entry.line, description: describeSource(entry.text) });

  const description = prose(
    `${f.message} saas-audit rates this ${f.severity}; that is its own static rating, not a demonstrated impact. Suggested change: ${f.fix}`,
    prose(f.title, f.rule),
  );
  const common = {
    fingerprint,
    title: prose(f.title, f.rule),
    description,
    claimed_root_cause: plan.claim,
    trace,
    evidence,
  };
  const rank = SEVERITY_RANK[f.severity] ?? 0;
  if (c.suppressedBy !== null) return { record: { verdict: "rejected", ...common, reason: rejectionReason(c.suppressedBy) }, rank };
  const blockers = [STATIC_ONLY_BLOCKER, ...plan.blockers];
  return {
    record: {
      verdict: "needs_validation",
      ...common,
      blockers,
      validation_plan: { local: plan.local, ...(plan.deployment ? { deployment: plan.deployment } : {}) },
    },
    rank,
  };
}

function byLocation(a: Candidate, b: Candidate): number {
  return a.finding.line - b.finding.line || a.order - b.order;
}

function toCandidates(result: AuditResult): Candidate[] {
  const out: Candidate[] = [];
  result.findings.forEach((finding, i) => out.push({ finding, suppressedBy: null, order: i }));
  result.suppressed.forEach((finding: SuppressedFinding, i) => out.push({ finding, suppressedBy: finding.suppressedBy, order: result.findings.length + i }));
  return out;
}

/** Fingerprints for every candidate. Findings that share an identity are told apart by their order in the file. */
function assignFingerprints(candidates: readonly Candidate[]): Map<Candidate, string> {
  const groups = new Map<string, Candidate[]>();
  for (const c of candidates) {
    const base = fingerprintBase(c.finding);
    const list = groups.get(base) ?? [];
    list.push(c);
    groups.set(base, list);
  }
  const out = new Map<Candidate, string>();
  for (const [base, list] of groups) {
    list.sort(byLocation).forEach((c, i) => out.set(c, i === 0 ? base : `${base}@${i + 1}`));
  }
  return out;
}

function recordBytes(record: FindingRecord): number {
  const text = JSON.stringify(record, null, 2);
  let lines = 1;
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) lines++;
  // the text itself, two spaces of indentation per line, and the comma and line break between records
  return Buffer.byteLength(text) + 2 * lines + 2;
}

function tally(omitted: Map<OmissionReason, number>, reason: OmissionReason, count = 1): void {
  omitted.set(reason, (omitted.get(reason) ?? 0) + count);
}

/**
 * Builds the export: needs_validation for every counted finding, rejected for every silenced one,
 * sorted by fingerprint. Findings the format cannot hold are counted in `omitted`.
 *
 * When the limits bite, records are taken in order of the tool's severity (then fingerprint) until the
 * first one that does not fit; it and every record after it are counted. A silenced finding keeps the
 * severity rank of the finding it was, so a silenced critical outranks a live medium.
 */
export function exportFindings(result: AuditResult): FindingsExport {
  const candidates = toCandidates(result);
  const fingerprints = assignFingerprints(candidates);
  const omitted = new Map<OmissionReason, number>();

  const built: Built[] = [];
  for (const c of candidates) {
    const outcome = build(c, fingerprints.get(c) ?? fingerprintBase(c.finding));
    if (typeof outcome === "string") tally(omitted, outcome);
    else built.push(outcome);
  }

  // when the format's limits are exceeded, stop at the first record that does not fit
  built.sort((a, b) => b.rank - a.rank || (a.record.fingerprint < b.record.fingerprint ? -1 : a.record.fingerprint > b.record.fingerprint ? 1 : 0));
  const kept: FindingRecord[] = [];
  let bytes = 16;
  for (const [i, { record }] of built.entries()) {
    if (kept.length >= MAX_RECORDS) {
      tally(omitted, "record-limit", built.length - i);
      break;
    }
    const size = recordBytes(record);
    if (bytes + size > MAX_BYTES) {
      tally(omitted, "size-limit", built.length - i);
      break;
    }
    bytes += size;
    kept.push(record);
  }
  kept.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));

  return {
    records: kept,
    omitted: [...omitted].map(([reason, count]) => ({ reason, count })),
    text: JSON.stringify(kept, null, 2) + "\n",
  };
}

/** One line per kind of omission, for stderr. */
export function omissionLines(omitted: readonly Omission[]): string[] {
  return omitted.map((o) => `findings export: ${o.count} finding${o.count === 1 ? "" : "s"} left out: ${OMISSION_TEXT[o.reason]}`);
}
