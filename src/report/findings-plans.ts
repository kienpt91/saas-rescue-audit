/**
 * What the findings export says about each rule: the claim, why a static result cannot settle it, and
 * how to test it. Every line is written once here so the export and its documentation cannot drift
 * apart (`test/findings.test.ts` checks that every rule in the catalog has a plan and no plan is orphaned).
 */

export interface RulePlan {
  /** What the finding claims is wrong, in one sentence that does not depend on the project. */
  claim: string;
  /** Why the static result cannot stand as a confirmed finding, beyond the limit that applies to every rule. */
  blockers: readonly string[];
  /** How to test the claim on a developer machine without touching production. */
  local: string;
  /** How to test it on the deployed system, for claims the repository alone cannot settle. */
  deployment?: string;
  /** What the primary location is, for a finding whose rule records no other site. */
  sink: string;
  /** Kind of the only trace step when the finding has one place: the weak spot, or the entry that is the weak spot. */
  single: "sink" | "entrypoint";
}

/** The limit shared by every finding the tool produces. It is the first blocker of every needs_validation record. */
export const STATIC_ONLY_BLOCKER = "Static analysis only: saas-audit read the source files and ran nothing, so no request, query or execution has shown this behaviour.";

const PROOF_AUDIT = "Run proof-audit against the migrations: it applies them to a throwaway PostgreSQL and probes the table as the anon role and as signed-in users.";

export const RULE_PLANS: Readonly<Record<string, RulePlan>> = {
  "supabase-rls-missing": {
    claim: "A table in the public schema is created without ENABLE ROW LEVEL SECURITY, so the REST API serves its rows to the anon role.",
    blockers: ["Only the migration files were read: tables and policies changed in the Supabase dashboard, and migrations that were never applied, are not reflected."],
    local: `${PROOF_AUDIT} A read and a write as anon that return rows or succeed confirm it.`,
    deployment: "On the deployed project, select relrowsecurity from pg_class for the table, and request the table through the REST API with the anon key.",
    sink: "The table is created here with no ENABLE ROW LEVEL SECURITY statement for it in the migrations",
    single: "sink",
  },
  "supabase-policy-permissive": {
    claim: "A row level security policy is always true, or lets the anon role write, so it does not restrict who can read or change rows.",
    blockers: ["The policy expression was folded to a constant from its SQL text; no database evaluated it.", "Grants, role membership and the other policies on the table were not combined by a database."],
    local: `${PROOF_AUDIT} A cross-user or anonymous read or write that succeeds confirms it.`,
    deployment: "On the deployed project, read the policy from pg_policies and repeat the anon and cross-user requests through the REST API.",
    sink: "The policy is defined here",
    single: "sink",
  },
  "supabase-policy-missing": {
    claim: "Row level security is enabled on a table that has no policy for client roles, so every client request is denied.",
    blockers: ["Whether the table is meant to be reached only through the service role, or the application is broken, depends on code and settings outside the migrations."],
    local: `${PROOF_AUDIT} Denied reads and writes confirm the table is closed to clients; then check whether application code reads it with a user token.`,
    deployment: "On the deployed project, list the policies of the table with pg_policies.",
    sink: "The table is created here and has row level security but no policy for client roles",
    single: "sink",
  },
  "supabase-tenant-unscoped": {
    claim: "A table has an owner or tenant column that none of its policies ties to the caller, so users the policies admit can reach each other's rows.",
    blockers: ["Policy expressions are matched to the owner column by their SQL text; no database evaluated them as two different users."],
    local: `${PROOF_AUDIT} Create rows for two users and read and change user B's rows as user A: success confirms it.`,
    deployment: "On the deployed project, repeat the two-user read and write through the REST API with two real sessions.",
    sink: "The table is created here and no policy compares its owner column with the caller",
    single: "sink",
  },
  "secret-in-client": {
    claim: "A server secret is read in client-side code, or a NEXT_PUBLIC_ variable that names a secret is published in the browser bundle.",
    blockers: ["Whether the value is a real secret, and which environment variables the production build sees, is not in the repository."],
    local: "Build the app with a distinctive placeholder value for the variable in a local env file, then search the build output (.next/static) for that placeholder: a hit means the value reaches the browser.",
    deployment: "Load the deployed site, search the downloaded scripts for the variable name or the value prefix, and rotate the secret if it is there.",
    sink: "The secret is referenced here in code or configuration that is bundled for the browser",
    single: "sink",
  },
  "secret-committed-env": {
    claim: "An environment file is tracked by git, or not covered by .gitignore, so credentials in it are committed or will be.",
    blockers: ["The git index and the .gitignore files were parsed without running git; history was not searched.", "Whether the file holds live credentials was not tested."],
    local: "In the real clone, run git ls-files and git check-ignore -v on the file, and git log --all -- on its path to see whether it was ever committed.",
    sink: "The environment file is here",
    single: "sink",
  },
  "secret-hardcoded": {
    claim: "A credential-shaped value is written in a source or template file.",
    blockers: ["The value matched a known key shape or an entropy heuristic; a placeholder, revoked or test value looks the same as a live one.", "The value was not tried against the service that issued it."],
    local: "Check with the issuing provider's own tooling, from a trusted machine, whether the key is live, without pasting it into tickets or chat; rotate it if it is.",
    sink: "The credential-shaped value is here",
    single: "sink",
  },
  "stripe-webhook-unverified": {
    claim: "A Stripe webhook handler never verifies the Stripe-Signature header, so anyone who knows the URL can send it forged events.",
    blockers: ["Verification done by an imported helper, a middleware or a proxy under a name the tool does not recognise is not followed."],
    local: "Run the app locally and send the handler a checkout.session.completed event with no signature, then one with a forged signature (for example the Stripe CLI with the wrong signing secret): any 2xx answer or side effect confirms it.",
    deployment: "Send the same forged request to the deployed endpoint in Stripe test mode and look for the side effect.",
    sink: "The handler acts on the request without verifying its signature",
    single: "entrypoint",
  },
  "stripe-webhook-parse-before-verify": {
    claim: "A Stripe webhook handler parses or re-serialises the body before verifying the signature, which either breaks verification or means the verified bytes are not the ones used.",
    blockers: ["Which bytes reach the verifier depends on framework body handling that was inferred from the code, not observed."],
    local: "Send a correctly signed test event (Stripe CLI listen and trigger) to the local handler and check that it is accepted; then send the same payload re-serialised and check that it is rejected.",
    sink: "The body is parsed or re-serialised here before the signature is verified",
    single: "sink",
  },
  "stripe-webhook-no-idempotency": {
    claim: "A verified Stripe webhook handler never reads event.id, so a redelivered event runs its side effects twice.",
    blockers: ["A de-duplication step in an imported helper, a database constraint or a queue in front of the handler is not visible."],
    local: "Deliver the same signed event twice to the local handler and check that the side effects (credits, emails, plan changes) happen once.",
    sink: "The event is verified here and its id is never used to de-duplicate",
    single: "sink",
  },
  "stripe-webhook-unknown-event-error": {
    claim: "A Stripe webhook handler answers event types it does not handle with an error status or an exception, so Stripe retries and can disable the endpoint.",
    blockers: ["Which event types the endpoint is subscribed to is configured in the Stripe dashboard, not in the repository."],
    local: "Send a signed event of a type the handler does not handle and check that the response is 2xx.",
    deployment: "List the events the endpoint is subscribed to in the Stripe dashboard.",
    sink: "The branch for unhandled event types fails here",
    single: "sink",
  },
  "stripe-checkout-client-price": {
    claim: "The price, amount or line items of a Stripe Checkout Session or PaymentIntent come from the request, so the caller decides what it pays.",
    blockers: ["Server-side validation in an imported helper, or a Stripe-side restriction on prices, is not followed."],
    local: "In Stripe test mode, call the route with a smaller amount or a different price id than the app offers and compare the amount of the created session.",
    sink: "The amount, line items or price id are taken from the request here",
    single: "sink",
  },
  "stripe-customer-unchecked": {
    claim: "A Stripe customer, subscription or payment id from the request is passed to Stripe without being tied to the signed-in user.",
    blockers: ["An ownership check in an imported helper, or one done before this function is called, is not followed."],
    local: "In Stripe test mode, sign in as user A and call the route with user B's customer or subscription id: a response about B, or a portal session for B, confirms it.",
    sink: "An id from the request is passed to Stripe here",
    single: "sink",
  },
  "api-route-no-auth": {
    claim: "A route handler or server action reads or writes data without calling any recognised authentication helper.",
    blockers: ["Authentication done by middleware, a wrapper or an imported helper under a name the tool does not recognise is not followed.", "Whether the data is meant to be public was not decided."],
    local: "Call the route with no session cookie and no Authorization header: any data returned or changed, instead of 401 or 403, confirms it.",
    deployment: "Repeat the unauthenticated call against the deployed URL, where middleware and platform rules also apply.",
    sink: "Data is read or written here with no recognised authentication check in the handler",
    single: "sink",
  },
  "api-idor": {
    claim: "A record is chosen by an id from the request with no ownership filter, or a row owner is set from client input.",
    blockers: ["Row level security, or an ownership check in an imported helper, may already restrict the query; the tool does not know which database client it runs with."],
    local: "Create records for two users, then as user A request user B's record id (or create a row with B's owner id): returned or changed data confirms it.",
    sink: "The query is filtered only by a value the caller controls",
    single: "sink",
  },
  "unsafe-html": {
    claim: "Non-constant input reaches an HTML sink (dangerouslySetInnerHTML, innerHTML, insertAdjacentHTML, document.write) without a recognised sanitizer.",
    blockers: ["Whether a user can control the value was not traced across files; it may be trusted content.", "A sanitizer under a name the tool does not recognise is not followed."],
    local: "Render the component in a browser or a jsdom test with a harmless marker payload such as an image tag with an onerror handler that sets a flag: the flag being set confirms it.",
    sink: "The HTML sink is here",
    single: "sink",
  },
  "open-redirect": {
    claim: "A redirect target comes from the request and is not validated before the redirect.",
    blockers: ["Validation in an imported helper, or an allow-list applied elsewhere, is not followed."],
    local: "Request the route with the redirect parameter set to an absolute URL on another host, and to a protocol-relative URL: a Location header that points there confirms it.",
    sink: "The redirect with a request-controlled target is here",
    single: "sink",
  },
  "cors-wildcard-credentials": {
    claim: "Access-Control-Allow-Origin is a wildcard or reflects the request origin while credentials are allowed.",
    blockers: ["Headers added or overwritten by middleware, the platform or a CDN are not visible."],
    local: "Send a request with an Origin header from another site and a session cookie, and read the Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers.",
    deployment: "Send the same request to the deployed URL, after the platform and CDN have applied their headers.",
    sink: "The CORS headers are set here",
    single: "sink",
  },
  "no-rate-limit": {
    claim: "An authentication or webhook route has no recognisable rate limiting.",
    blockers: ["Rate limiting by the platform, a WAF or a CDN is configured outside the repository."],
    local: "Send a burst of requests (for example 100 within a minute) to the route on a local instance and check whether any answer is 429.",
    deployment: "Repeat the burst against the deployed URL and check the platform's rate-limit settings.",
    sink: "This route has no recognised rate limiting",
    single: "entrypoint",
  },
  "build-checks-disabled": {
    claim: "next build is configured to ignore TypeScript or lint errors, so they ship unnoticed.",
    blockers: ["How many errors the flag hides was not measured."],
    local: "In a clean clone, run npx tsc --noEmit and the project's lint command: the errors they list are what the flag hides.",
    sink: "The build check is switched off here",
    single: "sink",
  },
  "security-headers": {
    claim: "No security headers are configured in the project, or one is weakened.",
    blockers: ["Headers added by the hosting platform, a CDN or a reverse proxy are not visible."],
    local: "Start the app locally and read the response headers of a page (for example with curl -I).",
    deployment: "Read the response headers of the deployed URL, where the platform and CDN may add some.",
    sink: "Security headers would be configured here",
    single: "sink",
  },
  "deps-unpinned": {
    claim: "A dependency is declared as * or latest, or the project has no lockfile, so installs are not reproducible.",
    blockers: ["The versions actually resolved today were not looked up; the tool does not use the network."],
    local: "Install twice in clean containers at different times, or run npm install --package-lock-only, and compare the resolved versions of the unpinned packages.",
    sink: "The dependency declaration is here",
    single: "sink",
  },
};

/** Used for a rule id that has no plan (a finding built by hand or by a newer version of the tool). */
export const FALLBACK_PLAN: RulePlan = {
  claim: "The rule reported a weakness at this location; the description explains what it saw.",
  blockers: ["The rule has no validation notes in this version of the export."],
  local: "Reproduce the behaviour described in the description on a local copy of the project and record the request and the response.",
  sink: "The rule reported this location",
  single: "sink",
};
