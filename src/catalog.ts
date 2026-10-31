import type { RuleInfo } from "./types.js";

export const RULES: readonly RuleInfo[] = [
  { id: "supabase-rls-missing", family: "supabase", severity: "high/critical", summary: "Table created in a public-schema migration without ENABLE ROW LEVEL SECURITY." },
  { id: "supabase-policy-permissive", family: "supabase", severity: "medium-critical", summary: "Policy whose USING or WITH CHECK is always true (true, 1 = 1, true or x, not false, ...), or a write policy for the anon role." },
  { id: "supabase-policy-missing", family: "supabase", severity: "medium", summary: "Table has row level security enabled but no policy for client roles." },
  { id: "supabase-tenant-unscoped", family: "supabase", severity: "high", summary: "Table has an owner/tenant column that no policy ties to the caller (auth.uid(), auth.jwt() or a membership function)." },
  { id: "secret-in-client", family: "secrets", severity: "critical/high", summary: "Server secret read in a client component, or a secret published through a NEXT_PUBLIC_ variable." },
  { id: "secret-committed-env", family: "secrets", severity: "high/critical", summary: ".env file that is tracked by git or not covered by .gitignore." },
  { id: "secret-hardcoded", family: "secrets", severity: "critical-medium", summary: "Key-shaped or high-entropy secret literal in source." },
  { id: "stripe-webhook-unverified", family: "stripe", severity: "critical", summary: "Stripe webhook handler with no reachable webhooks.constructEvent call (or verification helper named in authHelpers)." },
  { id: "stripe-webhook-parse-before-verify", family: "stripe", severity: "high", summary: "Request body parsed as JSON before the signature is verified." },
  { id: "stripe-webhook-no-idempotency", family: "stripe", severity: "medium", summary: "Verified webhook handler that never uses event.id to deduplicate." },
  { id: "stripe-webhook-unknown-event-error", family: "stripe", severity: "low", summary: "Unknown event types answered with an error status or an exception." },
  { id: "stripe-checkout-client-price", family: "stripe", severity: "high/medium", summary: "Price or amount taken from client input when creating a Checkout Session or PaymentIntent." },
  { id: "stripe-customer-unchecked", family: "stripe", severity: "high", summary: "Stripe customer or subscription id taken from client input without an ownership lookup." },
  { id: "api-route-no-auth", family: "auth", severity: "critical/high", summary: "Route handler or server action reads or writes data without a recognizable auth check." },
  { id: "api-idor", family: "auth", severity: "high", summary: "Record id or owner column taken from client input without an ownership filter." },
  { id: "unsafe-html", family: "injection", severity: "high/medium", summary: "dangerouslySetInnerHTML or innerHTML with non-constant input." },
  { id: "open-redirect", family: "injection", severity: "medium", summary: "Redirect target taken from request input without validation." },
  { id: "cors-wildcard-credentials", family: "config", severity: "high", summary: "Access-Control-Allow-Origin with a wildcard or reflected origin next to credentials." },
  { id: "no-rate-limit", family: "config", severity: "info", summary: "Auth or webhook route with no recognizable rate limiting." },
  { id: "build-checks-disabled", family: "config", severity: "medium", summary: "next.config skips type checking or linting during build." },
  { id: "security-headers", family: "config", severity: "info/low", summary: "No security headers configured, or a header weakened." },
  { id: "deps-unpinned", family: "config", severity: "low", summary: "package.json uses * or latest, or the project has no lockfile." },
];

export const RULE_IDS: ReadonlySet<string> = new Set(RULES.map((r) => r.id));
