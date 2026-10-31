import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { compileGlobs } from "./glob.js";
import { parseGitIndex } from "./gitindex.js";
import type { Config, Project } from "./types.js";

const SKIP_DIRS: Record<string, true> = {
  node_modules: true,
  ".git": true,
  ".next": true,
  dist: true,
  build: true,
  out: true,
  coverage: true,
  ".turbo": true,
  ".vercel": true,
  ".cache": true,
};

const CODE_EXT = /\.(?:[cm]?[jt]s|[jt]sx)$/;
export const MAX_FILE_BYTES = 1024 * 1024;
const MAX_INDEX_BYTES = 64 * 1024 * 1024;

export function isEnvFile(name: string): boolean {
  return name === ".env" || name.startsWith(".env.");
}

function isReadable(name: string): boolean {
  if (name.endsWith(".d.ts") || name.endsWith(".d.mts") || name.endsWith(".d.cts")) return false;
  return CODE_EXT.test(name) || name.endsWith(".sql") || isEnvFile(name) || name === ".gitignore" || name === "package.json";
}

/** Reads a project directory. Symlinks are not followed and nothing outside `root` is read. */
export function collectProject(root: string, config: Pick<Config, "ignorePaths">): Project {
  const ignored = compileGlobs(config.ignorePaths);
  const files = new Map<string, string>();
  const paths = new Set<string>();
  const warnings: string[] = [];

  const walk = (dir: string, rel: string): void => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const relPath = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS[entry.name] || ignored(relPath)) continue;
        walk(join(dir, entry.name), relPath);
      } else if (entry.isFile()) {
        if (ignored(relPath)) continue;
        paths.add(relPath);
        if (!isReadable(entry.name)) continue;
        const abs = join(dir, entry.name);
        if (statSync(abs).size > MAX_FILE_BYTES) {
          warnings.push(`${relPath}: skipped, larger than ${MAX_FILE_BYTES} bytes`);
          continue;
        }
        files.set(relPath, readFileSync(abs, "utf8"));
      }
    }
  };
  walk(root, "");

  let gitTracked: Set<string> | null = null;
  const indexPath = join(root, ".git", "index");
  if (existsSync(indexPath) && lstatSync(indexPath).isFile()) {
    if (statSync(indexPath).size > MAX_INDEX_BYTES) warnings.push(".git/index: skipped, too large");
    else {
      gitTracked = parseGitIndex(readFileSync(indexPath));
      if (gitTracked === null) warnings.push(".git/index: unsupported format, falling back to .gitignore rules only");
    }
  }
  return { root, files, paths, gitTracked, warnings };
}

/** Builds a project from in-memory files (used by tests and by library callers). */
export function projectFromFiles(files: Record<string, string>, options: { tracked?: string[]; root?: string } = {}): Project {
  const map = new Map(Object.entries(files));
  return {
    root: options.root ?? "<memory>",
    files: map,
    paths: new Set(map.keys()),
    gitTracked: options.tracked ? new Set(options.tracked) : null,
    warnings: [],
  };
}
