export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Higher number = more severe. */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

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
  /** The offending source text (secrets are redacted). */
  evidence: string;
  /** What to change. */
  fix: string;
}

/** A finding as produced by a rule: severity and evidence may be filled in by the engine. */
export type RawFinding = Omit<Finding, "evidence"> & { evidence?: string };

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
  /** Problems met while collecting (skipped large files, unreadable index). */
  warnings: string[];
}

export interface Config {
  /** Rule ids to switch off. */
  ignoreRules: string[];
  /** Globs of files and directories to skip. */
  ignorePaths: string[];
  /** Extra function names recognised as an authentication check. */
  authHelpers: string[];
  /** Globs of route files that are intentionally public (api-route-no-auth is skipped). */
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

export interface AuditResult {
  findings: Finding[];
  suppressed: Finding[];
  warnings: string[];
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
}
