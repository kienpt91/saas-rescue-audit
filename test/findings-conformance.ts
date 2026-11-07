/**
 * A small, independent conformance check for the findings.json shape, covering the two verdicts this
 * tool emits (`needs_validation` and `rejected`) and refusing `confirmed`. It is written from the public
 * description of the format and shares no code with the encoder under test, so a mistake in one is
 * unlikely to be repeated in the other. It returns every problem it finds as a readable string.
 */

const FINGERPRINT = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
const HAS_VISIBLE = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const BAD_PATH_CHAR = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\\:]/u;
const RESERVED = /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|(?:com|lpt)[0-9\u00b9\u00b2\u00b3])(?:\.|$)/iu;

export const MAX_RECORDS = 1000;
export const MAX_BYTES = 5 * 1024 * 1024;

const COMMON_KEYS = ["verdict", "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence"];
const KEYS: Record<string, readonly string[]> = {
  needs_validation: [...COMMON_KEYS, "blockers", "validation_plan"],
  rejected: [...COMMON_KEYS, "reason"],
};

type Obj = Record<string, unknown>;

function isObj(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function wellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

function visible(value: unknown): boolean {
  return typeof value === "string" && wellFormed(value) && HAS_VISIBLE.test(value);
}

export function isSafePath(value: unknown): boolean {
  if (typeof value !== "string" || value === "" || !wellFormed(value)) return false;
  if (BAD_PATH_CHAR.test(value) || value !== value.trim() || value.startsWith("/") || value.startsWith("~")) return false;
  return value.split("/").every((part) => part !== "" && part !== "." && part !== ".." && !/[ .]$/.test(part) && !RESERVED.test(part));
}

function exactKeys(value: Obj, allowed: readonly string[], required: readonly string[], where: string, errors: string[]): void {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) errors.push(`${where}: unexpected property ${JSON.stringify(key)}`);
  for (const key of required) if (!(key in value)) errors.push(`${where}: missing property ${JSON.stringify(key)}`);
}

function checkSites(record: Obj, field: "trace" | "evidence", where: string, errors: string[]): void {
  const list = record[field];
  if (!Array.isArray(list) || list.length === 0) {
    errors.push(`${where}.${field}: needs at least one item`);
    return;
  }
  const seen = new Set<string>();
  list.forEach((item: unknown, i) => {
    const at = `${where}.${field}[${i}]`;
    if (!isObj(item)) {
      errors.push(`${at}: not an object`);
      return;
    }
    const keys = field === "trace" ? ["kind", "file", "line", "scope", "description"] : ["file", "line", "description"];
    exactKeys(item, keys, keys, at, errors);
    if (!isSafePath(item["file"])) errors.push(`${at}.file: not a safe repository-relative path`);
    const line = item["line"];
    if (typeof line !== "number" || !Number.isInteger(line) || line < 1) errors.push(`${at}.line: must be an integer of at least 1`);
    if (!visible(item["description"])) errors.push(`${at}.description: needs visible text`);
    if (field === "trace" && !visible(item["scope"])) errors.push(`${at}.scope: needs visible text`);
    const key = JSON.stringify(item, Object.keys(item).sort());
    if (seen.has(key)) errors.push(`${at}: duplicate of an earlier item`);
    seen.add(key);
  });
  if (field === "trace") {
    const kinds = list.map((item: unknown) => (isObj(item) ? item["kind"] : undefined));
    if (kinds.some((k) => k !== "entrypoint" && k !== "sink" && k !== "propagation")) errors.push(`${where}.trace: kind must be entrypoint, propagation or sink`);
    if (kinds.length === 1) {
      if (kinds[0] !== "entrypoint" && kinds[0] !== "sink") errors.push(`${where}.trace: a one-step trace must be an entrypoint or a sink`);
    } else {
      if (kinds[0] !== "entrypoint") errors.push(`${where}.trace: must start with an entrypoint`);
      if (kinds[kinds.length - 1] !== "sink") errors.push(`${where}.trace: must end with a sink`);
      if (kinds.slice(1, -1).some((k) => k !== "propagation")) errors.push(`${where}.trace: steps between the ends must be propagation`);
    }
  }
}

function checkRecord(record: unknown, index: number, errors: string[]): void {
  const where = `$[${index}]`;
  if (!isObj(record)) {
    errors.push(`${where}: not an object`);
    return;
  }
  const verdict = record["verdict"];
  if (verdict === "confirmed") {
    errors.push(`${where}: saas-audit must never export a confirmed record (nothing it does demonstrates a finding)`);
    return;
  }
  const keys = typeof verdict === "string" ? KEYS[verdict] : undefined;
  if (keys === undefined) {
    errors.push(`${where}.verdict: must be needs_validation or rejected`);
    return;
  }
  exactKeys(record, keys, keys, where, errors);
  const fingerprint = record["fingerprint"];
  if (typeof fingerprint !== "string" || !FINGERPRINT.test(fingerprint)) errors.push(`${where}.fingerprint: does not match the fingerprint pattern`);
  for (const field of ["title", "description", "claimed_root_cause"]) if (!visible(record[field])) errors.push(`${where}.${field}: needs visible text`);
  checkSites(record, "trace", where, errors);
  checkSites(record, "evidence", where, errors);
  if (verdict === "rejected") {
    if (!visible(record["reason"])) errors.push(`${where}.reason: needs visible text`);
    return;
  }
  const blockers = record["blockers"];
  if (!Array.isArray(blockers) || blockers.length === 0) errors.push(`${where}.blockers: needs at least one item`);
  else {
    if (blockers.some((b: unknown) => !visible(b))) errors.push(`${where}.blockers: every item needs visible text`);
    if (new Set(blockers).size !== blockers.length) errors.push(`${where}.blockers: items must be unique`);
  }
  const plan = record["validation_plan"];
  if (!isObj(plan)) errors.push(`${where}.validation_plan: not an object`);
  else {
    exactKeys(plan, ["local", "deployment"], [], `${where}.validation_plan`, errors);
    for (const key of ["local", "deployment"]) if (key in plan && !visible(plan[key])) errors.push(`${where}.validation_plan.${key}: needs visible text`);
    if (!visible(plan["local"]) && !visible(plan["deployment"])) errors.push(`${where}.validation_plan: needs a local or a deployment plan`);
  }
}

/** Every way `doc` departs from the format, or an empty list when it conforms. */
export function conformanceErrors(doc: unknown): string[] {
  const errors: string[] = [];
  if (!Array.isArray(doc)) return ["$: the document must be an array"];
  if (doc.length > MAX_RECORDS) errors.push(`$: ${doc.length} records exceed the limit of ${MAX_RECORDS}`);
  doc.forEach((record: unknown, i) => checkRecord(record, i, errors));
  const seen = new Set<string>();
  let previous: string | null = null;
  doc.forEach((record: unknown, i) => {
    const fp = isObj(record) ? record["fingerprint"] : undefined;
    if (typeof fp !== "string") return;
    if (seen.has(fp)) errors.push(`$[${i}].fingerprint: duplicate`);
    seen.add(fp);
    if (previous !== null && previous > fp) errors.push(`$[${i}].fingerprint: records must be sorted by fingerprint`);
    previous = fp;
  });
  return errors;
}

/** Conformance of the text the command prints: it must parse, fit the size limit and conform. */
export function conformanceErrorsOfText(text: string): string[] {
  if (Buffer.byteLength(text) > MAX_BYTES) return [`$: ${Buffer.byteLength(text)} bytes exceed the limit of ${MAX_BYTES}`];
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return ["$: not valid JSON"];
  }
  return conformanceErrors(doc);
}
