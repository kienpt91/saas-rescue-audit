export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Higher number = more severe. */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** A place in the project that matters to a finding, and what happens there. */
export interface Site {
  /** Path relative to the project root, forward slashes. */
  file: string;
  /** 1-based. */
  line: number;
  /** What happens at this place, in one sentence. */
  note: string;
  /** The source text of the line, with credential-shaped substrings removed. */
  text?: string;
}

export interface Finding {
  rule: string;
  severity: Severity;
  /** Path relative to the project root, forward slashes. */
  file: string;
  /** 1-based. */
  line: number;
  title: string;
  /** Why it matters. */
  message: string;
  /** The offending source text, with credential-shaped substrings removed. */
  evidence: string;
  /** What to change. */
  fix: string;
  /**
   * The names that identify what the finding is about, in the order table, policy / handler / variable.
   * Together with the rule and the file they identify a finding without a line number, so the identity
   * survives edits that only move code. Absent for rules that have nothing better than their title.
   */
  subject?: string[];
  /** Where outside input or exposure enters (a handler, a table), when the rule knows it. */
  entry?: Site;
  /** Where the weakness is, when that is not `file:line`. */
  sink?: Site;
}

/** A finding as produced by a rule: evidence may be filled in by the engine. */
export type RawFinding = Omit<Finding, "evidence"> & {
  evidence?: string;
  /** Set by a rule when the project's config already declares this finding intentional. */
  suppressedBy?: string;
};

/** A finding that is not counted, and what silenced it. */
export type SuppressedFinding = Finding & { suppressedBy: string };

export interface RuleInfo {
  id: string;
  family: string;
  severity: string;
  summary: string;
}

export interface Project {
  /** Absolute project root; used only for display. */
  root: string;
  /** Relative path (forward slashes) to text, for every file the auditor reads. */
  files: ReadonlyMap<string, string>;
  /** Relative paths of every file found, including ones that are not read (lockfiles, images). */
  paths: ReadonlySet<string>;
  /** Paths listed in `.git/index`, or null when the project root has no readable index. */
  gitTracked: ReadonlySet<string> | null;
  /** Problems met while collecting that do not reduce coverage. */
  warnings: string[];
  /** Files, directories or whole parts of the project that were not read, as "path: reason". */
  skipped: string[];
  /** Directories skipped by name (dependencies, build output), as relative paths. */
  skippedDirs: string[];
  /** The first paths excluded by the config's ignorePaths. */
  ignoredByConfig: string[];
  /** How many paths ignorePaths excluded in all. */
  ignoredByConfigCount: number;
}

export interface Config {
  /** Rule ids to switch off. */
  ignoreRules: string[];
  /** Globs of files and directories to skip. */
  ignorePaths: string[];
  /** Extra function names recognised as an authentication check (and as webhook signature verification). */
  authHelpers: string[];
  /** Globs of route files that are intentionally public (api-route-no-auth is reported as suppressed). */
  publicRoutes: string[];
  /** Extra column names that mark a row owner or tenant. */
  tenantColumns: string[];
  /** Extra function names recognised as HTML sanitizers. */
  sanitizers: string[];
  /** Extra identifiers recognised as database clients. */
  dataAccessRoots: string[];
  /** Extra function names recognised as idempotency helpers in webhook handlers. */
  idempotencyHelpers: string[];
  /** Extra function names recognised as rate limiters. */
  rateLimiters: string[];
}

/** What shaped this run, printed in every report so a reader can see what was excluded. */
export interface EffectiveConfig extends Config {
  /** Config file the settings came from, or null when none was used. */
  source: string | null;
  /** Directories skipped by name. */
  skippedDirs: string[];
  /** Number of paths excluded by ignorePaths. */
  ignoredPathCount: number;
}

export interface AuditResult {
  findings: Finding[];
  suppressed: SuppressedFinding[];
  warnings: string[];
  /** Parts of the project that were not analysed. A non-empty list means the audit is incomplete. */
  skipped: string[];
  stats: {
    filesScanned: number;
    sourceFiles: number;
    sqlFiles: number;
    tablesFound: number;
    policiesFound: number;
    routeHandlers: number;
    serverActions: number;
    clientComponents: number;
  };
  /** Things the audit could not assess for this particular project. */
  notes: string[];
  config: EffectiveConfig;
}
