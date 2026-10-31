/**
 * Evaluates .gitignore files (root and nested) against project-relative paths.
 * Supports the common subset: comments, negation, directory-only patterns,
 * anchored patterns and `*`, `**`, `?`, `[...]`. It does not read global excludes
 * or `.git/info/exclude`. Patterns that are too long or too complicated are skipped
 * with a warning instead of being compiled.
 */
import { GlobError, matchGlob, parseGlob, type Glob } from "./glob.js";

export const MAX_RULES = 5000;

interface Rule {
  /** Directory (relative to the project root, no trailing slash) the .gitignore lives in; "" for the root. */
  base: string;
  glob: Glob;
  negate: boolean;
  dirOnly: boolean;
}

export class GitIgnore {
  private readonly rules: Rule[] = [];
  /** Lines that could not be used, as "path:line: reason". */
  readonly warnings: string[] = [];

  /** `files` maps relative paths to text; every entry named `.gitignore` is used. */
  constructor(files: ReadonlyMap<string, string>) {
    const gitignores = [...files.entries()].filter(([p]) => p === ".gitignore" || p.endsWith("/.gitignore")).sort((a, b) => a[0].split("/").length - b[0].split("/").length);
    for (const [path, text] of gitignores) {
      const base = path === ".gitignore" ? "" : path.slice(0, -"/.gitignore".length);
      this.addFile(path, base, text);
    }
  }

  private addFile(path: string, base: string, text: string): void {
    const lines = text.split("\n");
    for (let idx = 0; idx < lines.length; idx++) {
      let line = lines[idx]!;
      if (line.endsWith("\r")) line = line.slice(0, -1);
      line = line.trimEnd();
      if (line === "" || line.startsWith("#")) continue;
      if (this.rules.length >= MAX_RULES) {
        this.warnings.push(`${path}:${idx + 1}: more than ${MAX_RULES} rules, the rest of the file is ignored`);
        return;
      }
      let negate = false;
      if (line.startsWith("!")) {
        negate = true;
        line = line.slice(1);
      }
      if (line.startsWith("\\#") || line.startsWith("\\!")) line = line.slice(1);
      let dirOnly = false;
      if (line.endsWith("/")) {
        dirOnly = true;
        line = line.slice(0, -1);
      }
      if (line === "") continue;
      const anchored = line.includes("/");
      if (line.startsWith("/")) line = line.slice(1);
      try {
        const glob = parseGlob(anchored ? line : `**/${line}`);
        this.rules.push({ base, glob, negate, dirOnly });
      } catch (error) {
        if (!(error instanceof GlobError)) throw error;
        this.warnings.push(`${path}:${idx + 1}: pattern skipped (${error.message})`);
      }
    }
  }

  /** Whether git would ignore this file (a file inside an ignored directory is ignored). */
  isIgnored(path: string): boolean {
    const parts = path.split("/");
    for (let i = 1; i < parts.length; i++) {
      if (this.match(parts.slice(0, i).join("/"), true)) return true;
    }
    return this.match(path, false);
  }

  private match(path: string, isDir: boolean): boolean {
    let ignored = false;
    for (const rule of this.rules) {
      if (rule.base !== "" && !path.startsWith(rule.base + "/")) continue;
      if (rule.dirOnly && !isDir) continue;
      const rel = rule.base === "" ? path : path.slice(rule.base.length + 1);
      if (matchGlob(rule.glob, rel)) ignored = !rule.negate;
    }
    return ignored;
  }
}
