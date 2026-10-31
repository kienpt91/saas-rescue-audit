import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, type Dirent } from "node:fs";
import { join } from "node:path";
import { compileGlobs } from "./glob.js";
import { parseGitIndex } from "./gitindex.js";
import { DEFAULT_LIMITS, type Limits } from "./limits.js";
import type { Config, Project } from "./types.js";

/** Directories that never hold project source, wherever they appear. */
const ALWAYS_SKIPPED: Record<string, true> = { node_modules: true, ".git": true, ".next": true, ".turbo": true, ".vercel": true, ".cache": true };
/** Build output: skipped only where it is a package's own build directory, so a route segment called "build" is still audited. */
const BUILD_OUTPUT: Record<string, true> = { dist: true, build: true, out: true, coverage: true };

const CODE_EXT = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const MAX_INDEX_BYTES = 64 * 1024 * 1024;
/** Longest list of paths kept for reporting what was skipped or excluded. */
const MAX_LISTED = 50;

export function isEnvFile(name: string): boolean {
  return name === ".env" || name.startsWith(".env.");
}

function isReadable(name: string): boolean {
  if (name.endsWith(".d.ts") || name.endsWith(".d.mts") || name.endsWith(".d.cts")) return false;
  return CODE_EXT.test(name) || name.endsWith(".sql") || isEnvFile(name) || name === ".gitignore" || name === "package.json";
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : "error";
}

/**
 * Reads at most `maxBytes` from a regular file. The file is opened without following symlinks and
 * without blocking (so a FIFO swapped in after the directory listing cannot hang the run), and the
 * type and size are checked on the open descriptor rather than on the path.
 */
export function readBytes(path: string, maxBytes: number, options: { followSymlinks?: boolean } = {}): { data: Buffer } | { skip: string } {
  const flags = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (options.followSymlinks ? 0 : (constants.O_NOFOLLOW ?? 0));
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch (error) {
    return { skip: `could not be opened (${errorCode(error)})` };
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { skip: "not a regular file" };
    if (stat.size > maxBytes) return { skip: `larger than ${maxBytes} bytes` };
    const buffer = Buffer.alloc(Math.min(stat.size, maxBytes) + 1);
    let length = 0;
    while (length < buffer.length) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
    }
    if (length > maxBytes) return { skip: `larger than ${maxBytes} bytes` };
    return { data: buffer.subarray(0, length) };
  } catch (error) {
    return { skip: `could not be read (${errorCode(error)})` };
  } finally {
    closeSync(fd);
  }
}

/** `readBytes` decoded as UTF-8 text, without a byte order mark. */
export function readRegularFile(path: string, maxBytes: number, options: { followSymlinks?: boolean } = {}): { text: string; bytes: number } | { skip: string } {
  const result = readBytes(path, maxBytes, options);
  if ("skip" in result) return result;
  return { text: result.data.toString("utf8").replace(/^\uFEFF/, ""), bytes: result.data.length };
}

/**
 * Reads a project directory. Symlinks are not followed, nothing outside `root` is read, and
 * anything that cannot be read, or that exceeds a limit, is recorded in `skipped` rather than
 * stopping the run or being dropped silently.
 */
export function collectProject(root: string, config: Pick<Config, "ignorePaths">, limits: Limits = DEFAULT_LIMITS): Project {
  const ignored = compileGlobs(config.ignorePaths);
  const files = new Map<string, string>();
  const paths = new Set<string>();
  const warnings: string[] = [];
  const skipped: string[] = [];
  const skippedDirs: string[] = [];
  const ignoredByConfig: string[] = [];
  let ignoredCount = 0;
  let totalBytes = 0;
  let stopped = false;
  const symlinks: string[] = [];

  const noteIgnored = (relPath: string): void => {
    ignoredCount++;
    if (ignoredByConfig.length < MAX_LISTED) ignoredByConfig.push(relPath);
  };

  const walk = (dir: string, rel: string, depth: number): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch (error) {
      skipped.push(`${rel === "" ? "." : rel}: directory could not be read (${errorCode(error)})`);
      return;
    }
    const isPackageRoot = entries.some((e) => e.name === "package.json" && e.isFile());
    for (const entry of entries) {
      if (stopped) return;
      const relPath = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        symlinks.push(relPath);
        continue;
      }
      if (entry.isDirectory()) {
        if (ALWAYS_SKIPPED[entry.name] === true || (BUILD_OUTPUT[entry.name] === true && isPackageRoot)) {
          if (skippedDirs.length < MAX_LISTED) skippedDirs.push(relPath);
        } else if (ignored(relPath)) noteIgnored(relPath);
        else if (depth + 1 > limits.maxDirDepth) skipped.push(`${relPath}: directory nests deeper than ${limits.maxDirDepth} levels`);
        else walk(join(dir, entry.name), relPath, depth + 1);
      } else if (entry.isFile()) {
        if (ignored(relPath)) {
          noteIgnored(relPath);
          continue;
        }
        paths.add(relPath);
        if (!isReadable(entry.name)) continue;
        if (files.size >= limits.maxFiles) {
          skipped.push(`${relPath}: not read, the limit of ${limits.maxFiles} files was reached (further files are not listed)`);
          stopped = true;
          return;
        }
        const result = readRegularFile(join(dir, entry.name), limits.maxFileBytes);
        if ("skip" in result) {
          skipped.push(`${relPath}: not read, ${result.skip}`);
          continue;
        }
        totalBytes += result.bytes;
        if (totalBytes > limits.maxTotalBytes) {
          skipped.push(`${relPath}: not read, the limit of ${limits.maxTotalBytes} bytes in total was reached (further files are not listed)`);
          stopped = true;
          return;
        }
        files.set(relPath, result.text);
      }
    }
  };
  walk(root, "", 0);

  if (symlinks.length > 0) {
    const shown = symlinks.slice(0, 5).join(", ");
    warnings.push(`${symlinks.length} symbolic link${symlinks.length === 1 ? " was" : "s were"} not followed: ${shown}${symlinks.length > 5 ? `, and ${symlinks.length - 5} more` : ""}`);
  }
  const gitTracked = readGitIndex(root, warnings);
  return { root, files, paths, gitTracked, warnings, skipped, skippedDirs, ignoredByConfig, ignoredByConfigCount: ignoredCount };
}

/** Reads the tracked paths from `<root>/.git/index`. A `.git` that is a symlink or a file is not trusted. */
function readGitIndex(root: string, warnings: string[]): Set<string> | null {
  let gitDir;
  try {
    gitDir = lstatSync(join(root, ".git"));
  } catch {
    return null;
  }
  if (!gitDir.isDirectory()) {
    warnings.push(".git is not a plain directory (a symlink or a worktree file), so tracked files were judged from .gitignore rules only");
    return null;
  }
  const result = readBytes(join(root, ".git", "index"), MAX_INDEX_BYTES);
  if ("skip" in result) {
    // a missing index is normal for a fresh repository
    if (!result.skip.includes("ENOENT")) warnings.push(`.git/index: ${result.skip}, falling back to .gitignore rules only`);
    return null;
  }
  const tracked = parseGitIndex(result.data);
  if (tracked === null) warnings.push(".git/index: unsupported format, falling back to .gitignore rules only");
  return tracked;
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
    skipped: [],
    skippedDirs: [],
    ignoredByConfig: [],
    ignoredByConfigCount: 0,
  };
}
