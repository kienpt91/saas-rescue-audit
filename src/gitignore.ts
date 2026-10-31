/**
 * Evaluates .gitignore files (root and nested) against project-relative paths.
 * Supports the common subset: comments, negation, directory-only patterns,
 * anchored patterns and `*`, `**`, `?`, `[...]`. It does not read global excludes
 * or `.git/info/exclude`.
 */
import { globSource } from "./glob.js";

interface Rule {
  /** Directory (relative to the project root, no trailing slash) the .gitignore lives in; "" for the root. */
  base: string;
  regex: RegExp;
  negate: boolean;
  dirOnly: boolean;
}

function parseRules(base: string, text: string): Rule[] {
  const rules: Rule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/(?<!\\)\s+$/, "");
    if (line === "" || line.startsWith("#")) continue;
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
    const src = globSource(line);
    const regex = new RegExp(anchored ? `^${src}$` : `^(?:.*/)?${src}$`);
    rules.push({ base, regex, negate, dirOnly });
  }
  return rules;
}

export class GitIgnore {
  private readonly rules: Rule[] = [];

  /** `files` maps relative paths to text; every entry named `.gitignore` is used. */
  constructor(files: ReadonlyMap<string, string>) {
    const gitignores = [...files.entries()].filter(([p]) => p === ".gitignore" || p.endsWith("/.gitignore")).sort((a, b) => a[0].split("/").length - b[0].split("/").length);
    for (const [p, text] of gitignores) {
      const base = p === ".gitignore" ? "" : p.slice(0, -"/.gitignore".length);
      this.rules.push(...parseRules(base, text));
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
      if (rule.regex.test(rel)) ignored = !rule.negate;
    }
    return ignored;
  }
}
