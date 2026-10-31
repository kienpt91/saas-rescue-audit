#!/usr/bin/env node
import { existsSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { audit } from "./audit.js";
import { RULES } from "./catalog.js";
import { CONFIG_FILE, ConfigError, DEFAULT_CONFIG, MAX_CONFIG_BYTES, parseConfig } from "./config.js";
import { collectProject, readRegularFile } from "./project.js";
import { filterMinSeverity, projectName } from "./report/common.js";
import { renderHuman } from "./report/human.js";
import { renderJson } from "./report/json.js";
import { renderMarkdown } from "./report/markdown.js";
import { terminalText } from "./report/text.js";
import { SEVERITIES, SEVERITY_RANK, type Config, type Severity } from "./types.js";
import { TOOL_VERSION } from "./version.js";

export interface Io {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd: string;
  color: boolean;
}

const USAGE = `Usage: saas-audit [dir] [options]

Static audit of a Next.js + Supabase + Stripe project. Reads files only: no
network, no code execution.

Options:
  --json                  print a JSON report
  --markdown              print a Markdown report (client deliverable format)
  -o, --output <file>     write the report to a file instead of stdout
  --config <file>         config file (default: <dir>/${CONFIG_FILE})
  --min-severity <level>  hide findings below critical|high|medium|low|info
  --fail-on <level|none>  exit 1 when a finding at or above this level exists (default: low)
  --date <YYYY-MM-DD>     print a date in the Markdown header (omitted by default)
  --allow-incomplete      do not use exit code 3 when files were skipped or could not be analysed
  --no-color              disable colors
  --list-rules            list the rules and exit
  -h, --help              show this help
  -v, --version           show the version

Exit codes: 0 nothing at the fail-on level and the audit is complete, 1 findings,
2 usage or input error, 3 the audit is incomplete (files skipped by a size, count,
nesting or time limit, or unreadable) and there are no findings to report.
`;

interface Args {
  dir: string;
  json: boolean;
  markdown: boolean;
  output: string | null;
  config: string | null;
  minSeverity: Severity | null;
  failOn: Severity | "none";
  date: string | null;
  color: boolean | null;
  allowIncomplete: boolean;
  listRules: boolean;
  help: boolean;
  version: boolean;
}

class UsageError extends Error {
  override name = "UsageError";
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { dir: ".", json: false, markdown: false, output: null, config: null, minSeverity: null, failOn: "low", date: null, color: null, allowIncomplete: false, listRules: false, help: false, version: false };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const value = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case "--json":
        args.json = true;
        break;
      case "--markdown":
        args.markdown = true;
        break;
      case "-o":
      case "--output":
        args.output = value();
        break;
      case "--config":
        args.config = value();
        break;
      case "--min-severity": {
        const v = value();
        if (!isSeverity(v)) throw new UsageError(`--min-severity must be one of ${SEVERITIES.join(", ")}`);
        args.minSeverity = v;
        break;
      }
      case "--fail-on": {
        const v = value();
        if (v === "none") args.failOn = "none";
        else if (isSeverity(v)) args.failOn = v;
        else throw new UsageError(`--fail-on must be none or one of ${SEVERITIES.join(", ")}`);
        break;
      }
      case "--date": {
        const v = value();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) throw new UsageError("--date must look like 2026-01-31");
        args.date = v;
        break;
      }
      case "--allow-incomplete":
        args.allowIncomplete = true;
        break;
      case "--no-color":
        args.color = false;
        break;
      case "--list-rules":
        args.listRules = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      default:
        if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
        positional.push(a);
    }
  }
  if (positional.length > 1) throw new UsageError("only one directory can be audited at a time");
  if (positional[0]) args.dir = positional[0];
  if (args.json && args.markdown) throw new UsageError("--json and --markdown cannot be combined");
  return args;
}

/**
 * Reads the config file. The one found in the audited directory comes from the repository under audit,
 * so it is opened without following symlinks and only as a regular file of bounded size; a path given
 * with --config is the user's own choice and may be a symlink.
 */
function loadConfig(dir: string, explicit: string | null, cwd: string): { config: Config; source: string | null } {
  const path = explicit ? resolve(cwd, explicit) : resolve(dir, CONFIG_FILE);
  const result = readRegularFile(path, MAX_CONFIG_BYTES, { followSymlinks: explicit !== null });
  if ("skip" in result) {
    if (result.skip.includes("ENOENT")) {
      if (explicit) throw new UsageError(`config file not found: ${explicit}`);
      return { config: DEFAULT_CONFIG, source: null };
    }
    throw new ConfigError(`${explicit ?? CONFIG_FILE}: ${result.skip}`);
  }
  return { config: parseConfig(result.text, explicit ?? CONFIG_FILE), source: explicit ?? CONFIG_FILE };
}

/**
 * Entry point with injectable I/O. Returns the process exit code. Anything unexpected is reported as
 * an internal error (exit code 2) instead of a stack trace, which could quote text from the repository.
 */
export function run(argv: readonly string[], io: Io): number {
  try {
    return execute(argv, io);
  } catch (error) {
    io.stderr(`saas-audit: internal error: ${terminalText(error instanceof Error ? `${error.name}: ${error.message}` : "unknown error")}\n`);
    return 2;
  }
}

function execute(argv: readonly string[], io: Io): number {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    io.stderr(`${terminalText(e instanceof Error ? e.message : "invalid arguments")}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    io.stdout(USAGE);
    return 0;
  }
  if (args.version) {
    io.stdout(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (args.listRules) {
    io.stdout(RULES.map((r) => `${r.id.padEnd(36)} ${r.severity.padEnd(16)} ${r.summary}`).join("\n") + "\n");
    return 0;
  }

  const dir = resolve(io.cwd, args.dir);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    io.stderr(`not a directory: ${terminalText(args.dir)}\n`);
    return 2;
  }

  let config: Config;
  let configSource: string | null;
  try {
    ({ config, source: configSource } = loadConfig(dir, args.config, io.cwd));
  } catch (e) {
    if (e instanceof ConfigError || e instanceof UsageError) {
      io.stderr(`${terminalText(e.message)}\n`);
      return 2;
    }
    throw e;
  }

  const project = collectProject(dir, config);
  const full = audit(project, config, { configSource });
  const shown = args.minSeverity ? { ...full, findings: filterMinSeverity(full.findings, args.minSeverity) } : full;
  const name = projectName(project);

  let text: string;
  if (args.json) text = renderJson(shown, { name, version: TOOL_VERSION });
  else if (args.markdown) text = renderMarkdown(shown, { name, version: TOOL_VERSION, ...(args.date ? { date: args.date } : {}) });
  else text = renderHuman(shown, { name, version: TOOL_VERSION, color: args.color ?? io.color });

  if (args.output) {
    writeFileSync(resolve(io.cwd, args.output), text);
    io.stderr(`wrote ${terminalText(args.output)}\n`);
  } else io.stdout(text);

  if (args.failOn !== "none") {
    const threshold = SEVERITY_RANK[args.failOn];
    if (shown.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold)) return 1;
  }
  if (full.skipped.length > 0 && !args.allowIncomplete) {
    io.stderr(`audit incomplete: ${full.skipped.length} item${full.skipped.length === 1 ? " was" : "s were"} not analysed (exit code 3, see "Not analysed" in the report)\n`);
    return 3;
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const code = run(process.argv.slice(2), {
    stdout: (t) => process.stdout.write(t),
    stderr: (t) => process.stderr.write(t),
    cwd: process.cwd(),
    color: process.stdout.isTTY === true && !process.env["NO_COLOR"],
  });
  process.exitCode = code;
}
