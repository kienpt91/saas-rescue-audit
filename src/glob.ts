/**
 * Glob matching for config patterns and .gitignore rules, without regular expressions.
 * Supported: `*` and `?` (never across a slash), `[...]` classes with ranges and `!`/`^`
 * negation, `\` escapes, and `**` as a whole path segment (zero or more directories).
 *
 * Patterns come from the audited repository, so matching has to stay cheap whatever they
 * contain: the work is dynamic programming over (pattern part x path part), which is
 * polynomial and has no backtracking, patterns are capped at 256 characters and 16
 * wildcards, and a malformed class matches nothing instead of throwing.
 */

export const MAX_GLOB_LENGTH = 256;
export const MAX_WILDCARDS = 16;

export class GlobError extends Error {
  override name = "GlobError";
}

type Atom = { t: "lit"; c: string } | { t: "any" } | { t: "star" } | { t: "class"; negate: boolean; ranges: [string, string][] };

interface Segment {
  globstar: boolean;
  atoms: Atom[];
  /** The whole segment when it has no wildcard. */
  literal: string | null;
}

export interface Glob {
  segments: Segment[];
}

function parseClass(pattern: string, open: number): { atom: Atom; next: number } | null {
  let i = open + 1;
  let negate = false;
  if (pattern[i] === "!" || pattern[i] === "^") {
    negate = true;
    i++;
  }
  const ranges: [string, string][] = [];
  const start = i;
  while (i < pattern.length && (pattern[i] !== "]" || i === start)) {
    let lo = pattern[i]!;
    if (lo === "\\" && i + 1 < pattern.length) lo = pattern[++i]!;
    if (pattern[i + 1] === "-" && i + 2 < pattern.length && pattern[i + 2] !== "]") {
      let hi = pattern[i + 2]!;
      i += 2;
      if (hi === "\\" && i + 1 < pattern.length) hi = pattern[++i]!;
      ranges.push([lo, hi]);
    } else ranges.push([lo, lo]);
    i++;
  }
  if (i >= pattern.length) return null;
  return { atom: { t: "class", negate, ranges }, next: i + 1 };
}

function parseSegment(text: string): { segment: Segment; wildcards: number } {
  if (text === "**") return { segment: { globstar: true, atoms: [], literal: null }, wildcards: 1 };
  const atoms: Atom[] = [];
  let wildcards = 0;
  for (let i = 0; i < text.length; ) {
    const ch = text[i]!;
    if (ch === "\\" && i + 1 < text.length) {
      atoms.push({ t: "lit", c: text[i + 1]! });
      i += 2;
    } else if (ch === "*") {
      while (text[i] === "*") i++;
      atoms.push({ t: "star" });
      wildcards++;
    } else if (ch === "?") {
      atoms.push({ t: "any" });
      wildcards++;
      i++;
    } else if (ch === "[") {
      const parsed = parseClass(text, i);
      if (parsed) {
        atoms.push(parsed.atom);
        wildcards++;
        i = parsed.next;
      } else {
        atoms.push({ t: "lit", c: "[" });
        i++;
      }
    } else {
      atoms.push({ t: "lit", c: ch });
      i++;
    }
  }
  const literal = wildcards === 0 ? atoms.map((a) => (a.t === "lit" ? a.c : "")).join("") : null;
  return { segment: { globstar: false, atoms, literal }, wildcards };
}

/** Parses a pattern. Throws GlobError when it is longer than 256 characters or has more than 16 wildcards. */
export function parseGlob(pattern: string): Glob {
  if (pattern.length > MAX_GLOB_LENGTH) throw new GlobError(`longer than ${MAX_GLOB_LENGTH} characters`);
  const segments: Segment[] = [];
  let wildcards = 0;
  for (const part of pattern.split("/")) {
    if (part === "") continue;
    const parsed = parseSegment(part);
    wildcards += parsed.wildcards;
    segments.push(parsed.segment);
  }
  if (wildcards > MAX_WILDCARDS) throw new GlobError(`more than ${MAX_WILDCARDS} wildcards`);
  return { segments };
}

function atomMatches(atom: Atom, ch: string): boolean {
  if (atom.t === "lit") return atom.c === ch;
  if (atom.t === "any") return true;
  if (atom.t !== "class") return false;
  const inRange = atom.ranges.some(([lo, hi]) => ch >= lo && ch <= hi);
  return inRange !== atom.negate;
}

function matchSegment(seg: Segment, text: string): boolean {
  if (seg.literal !== null) return seg.literal === text;
  const n = text.length;
  let prev = new Uint8Array(n + 1);
  prev[0] = 1;
  for (const atom of seg.atoms) {
    const cur = new Uint8Array(n + 1);
    if (atom.t === "star") {
      cur[0] = prev[0]!;
      for (let j = 1; j <= n; j++) cur[j] = prev[j]! | cur[j - 1]!;
    } else {
      for (let j = 1; j <= n; j++) cur[j] = prev[j - 1]! & (atomMatches(atom, text[j - 1]!) ? 1 : 0);
    }
    prev = cur;
  }
  return prev[n] === 1;
}

/** Whether the glob matches the whole of `path` (forward slashes, no leading slash). */
export function matchGlob(glob: Glob, path: string): boolean {
  const parts = path.split("/");
  const s = parts.length;
  let prev = new Uint8Array(s + 1);
  prev[0] = 1;
  for (const seg of glob.segments) {
    const cur = new Uint8Array(s + 1);
    if (seg.globstar) {
      cur[0] = prev[0]!;
      for (let j = 1; j <= s; j++) cur[j] = prev[j]! | cur[j - 1]!;
    } else {
      for (let j = 1; j <= s; j++) cur[j] = prev[j - 1]! && matchSegment(seg, parts[j - 1]!) ? 1 : 0;
    }
    prev = cur;
  }
  return prev[s] === 1;
}

/**
 * Compiles config globs. A pattern matches a path when it matches the path itself or any
 * parent directory, so `scripts` and `scripts/**` both exclude `scripts/seed.ts`. Throws GlobError
 * for a pattern that is too long or has too many wildcards.
 */
export function compileGlobs(patterns: readonly string[]): (path: string) => boolean {
  const globs = patterns.map((p) => {
    const glob = parseGlob(p.replace(/^\.\//, ""));
    glob.segments.push({ globstar: true, atoms: [], literal: null });
    return glob;
  });
  return (path) => globs.some((g) => matchGlob(g, path));
}
