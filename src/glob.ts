/**
 * Minimal glob support for config patterns and .gitignore rules:
 * `*` (no slash), `**` (any depth), `?` and `[...]` classes.
 * Patterns are length-limited and runs of `*` are collapsed to bound backtracking.
 */

export const MAX_GLOB_LENGTH = 256;

/** Regular-expression source (no anchors) for a glob that is matched against forward-slash paths. */
export function globSource(pattern: string): string {
  const p = pattern.slice(0, MAX_GLOB_LENGTH).replace(/\*{3,}/g, "**");
  let out = "";
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === "*") {
      if (p[i + 1] === "*") {
        // `**/` matches zero or more directories; a trailing `**` matches anything
        if (p[i + 2] === "/") {
          out += "(?:[^/]+/)*";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else out += "[^/]*";
    } else if (ch === "?") out += "[^/]";
    else if (ch === "[") {
      const close = p.indexOf("]", i + 2);
      if (close === -1) out += "\\[";
      else {
        let body = p.slice(i + 1, close);
        if (body.startsWith("!")) body = "^" + body.slice(1);
        out += "[" + body.replace(/\\/g, "\\\\") + "]";
        i = close;
      }
    } else out += ch.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return out;
}

/**
 * Compiles a glob for config use. A pattern matches a path when it matches the path itself or
 * any parent directory, so `scripts` and `scripts/**` both exclude `scripts/seed.ts`.
 */
export function compileGlobs(patterns: readonly string[]): (path: string) => boolean {
  const regexes = patterns.map((p) => new RegExp(`^${globSource(p.replace(/^\.\//, "").replace(/\/+$/, ""))}(?:/.*)?$`));
  return (path) => regexes.some((r) => r.test(path));
}
