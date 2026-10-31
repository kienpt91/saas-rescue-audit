const windows = new Map<string, { count: number; resetAt: number }>();

/**
 * Fixed-window counter held in process memory. It only limits one server instance
 * and resets on deploy; behind several instances use a shared store.
 * Returns false when the key has used up its allowance for the current window.
 */
export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = windows.get(key);
  if (!entry || entry.resetAt <= now) {
    windows.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  entry.count += 1;
  return entry.count <= limit;
}
