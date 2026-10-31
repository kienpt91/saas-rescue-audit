/**
 * Resource limits for auditing a repository that may be hostile. Everything that
 * is cut off is reported (as a skipped file) and makes the run incomplete, which
 * the command line turns into a non-zero exit code.
 */
export interface Limits {
  /** Largest file that is read. */
  maxFileBytes: number;
  /** Most files that are read in one run. */
  maxFiles: number;
  /** Most bytes that are read in one run. */
  maxTotalBytes: number;
  /** Deepest directory level that is entered. */
  maxDirDepth: number;
  /** Deepest syntax tree that is analysed (the analysis is recursive). */
  maxAstDepth: number;
  /** Time one source or SQL file may take, across all rules. */
  fileBudgetMs: number;
  /** Time the whole analysis phase may take. */
  totalBudgetMs: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxFileBytes: 1024 * 1024,
  maxFiles: 20_000,
  maxTotalBytes: 64 * 1024 * 1024,
  maxDirDepth: 64,
  maxAstDepth: 1000,
  fileBudgetMs: 10_000,
  totalBudgetMs: 120_000,
};

export class BudgetError extends Error {
  override name = "BudgetError";
}

let deadline = Number.POSITIVE_INFINITY;
let counter = 0;

/** Cooperative deadline check for hot loops. Cheap: the clock is read once every 256 calls. */
export function tick(): void {
  if ((++counter & 255) !== 0) return;
  if (Date.now() > deadline) throw new BudgetError("time budget exceeded");
}

/** Runs `fn` with a deadline of `ms` from now (or the enclosing deadline, if sooner). */
export function withBudget<T>(ms: number, fn: () => T): T {
  const previous = deadline;
  deadline = Math.min(previous, Date.now() + ms);
  try {
    return fn();
  } finally {
    deadline = previous;
  }
}
