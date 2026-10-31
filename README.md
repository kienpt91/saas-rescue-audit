# saas-rescue-audit

`saas-audit` is a command-line static auditor for Next.js + Supabase + Stripe codebases that were put together quickly, often with coding agents, and now have to be made safe to run for real users. It reads a project directory and reports concrete findings: file, line, the offending source, why it matters and what to change. It uses no network and no language model, and the same input always gives the same output.

It is an example project. It has not been used on anyone's production system, it has not found a real vulnerability in anyone's code, and it is a set of heuristics, not a security product. Read [What it does not check](#what-it-does-not-check) before trusting a clean report.

```
$ saas-audit examples/vibe-app
saas-audit 0.1.0: vibe-app
Scanned 18 files: 14 JS/TS, 2 SQL (5 tables, 4 policies), 7 route handlers, 1 server action, 1 client component.

CRITICAL secret-in-client  .env.local:3
  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY publishes a secret to the browser
  Why:      Next.js inlines every NEXT_PUBLIC_ variable into the client bundle at build time (env file). A name containing a secret marker means the value is readable by every visitor.
  Evidence: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=…
  Fix:      Rename the variable without the NEXT_PUBLIC_ prefix, read it only in route handlers or server components, and rotate the key because it has already been exposed.

...

34 findings: 7 critical, 14 high, 6 medium, 4 low, 3 info.
```

(Output above is from a real run, shortened with `...`. The full output for the same project is in [examples/sample-report.md](examples/sample-report.md).)

## Run it in a container

Nothing here needs to be installed on your machine. These commands use the official Node image; the project is not published to a registry.

```sh
# 1. install exactly what the lockfile says (no install scripts) and compile
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work node:22 \
  sh -c 'npm ci --ignore-scripts && npm run build'

# 2. audit a directory: both mounts are read-only and the container has no network
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD":/work:ro -v /path/to/your/app:/audit:ro -w /work node:22 \
  node dist/cli.js /audit
```

Add `--json` or `--markdown` for the other formats, and `--output <file>` to write a file (the output directory then has to be mounted writable). The exit code is 0 when nothing at or above `--fail-on` (default `low`) was found, 1 when something was, and 2 for a usage or config error, so it can gate a CI job.

```
saas-audit [dir] [options]
  --json                  JSON report
  --markdown              Markdown report in client-deliverable format
  -o, --output <file>     write the report to a file
  --config <file>         config file (default: <dir>/saas-audit.config.json)
  --min-severity <level>  hide findings below critical|high|medium|low|info
  --fail-on <level|none>  exit 1 at or above this level (default: low)
  --date <YYYY-MM-DD>     print a date in the Markdown header (off by default, so output is reproducible)
  --no-color, --list-rules, --help, --version
```

## What it checks

Twenty-two rules in six families. Each one has positive and negative tests in `test/`.

| Family | Rule | What it reports |
| --- | --- | --- |
| Supabase RLS | `supabase-rls-missing` | A table created in a public-schema migration that never gets `ENABLE ROW LEVEL SECURITY` (critical when it has an owner column, otherwise high). |
| | `supabase-policy-permissive` | `USING (true)` / `WITH CHECK (true)` on a policy for client roles; any write policy that names the `anon` role. |
| | `supabase-policy-missing` | RLS is on but no policy exists for client roles. |
| | `supabase-tenant-unscoped` | The table has an owner or tenant column (`user_id`, `org_id`, ..., or any column that references `auth.users`) and no policy mentions it. |
| Secrets | `secret-in-client` | A server secret read in a `"use client"` file; a `NEXT_PUBLIC_*` name that contains `SERVICE_ROLE`, `SECRET`, `PRIVATE`, `PASSWORD`, ... in code, `.env` files or the `next.config` `env` block. |
| | `secret-committed-env` | An `.env*` file that is in the git index or not covered by `.gitignore`. |
| | `secret-hardcoded` | Known key shapes (Stripe, AWS, GitHub, Slack, JWTs with `role: service_role`, private key blocks, database URLs with passwords) and high-entropy literals assigned to secret-looking names. Values are redacted in the report. |
| Stripe | `stripe-webhook-unverified` | A webhook handler that never calls `constructEvent`. |
| | `stripe-webhook-parse-before-verify` | The body is parsed as JSON (or re-serialised) before verification, or `req.body` is used without `bodyParser: false`. |
| | `stripe-webhook-no-idempotency` | A verified handler that never reads `event.id`. |
| | `stripe-webhook-unknown-event-error` | The `default` branch or final `else` for event types returns a 4xx/5xx or throws. |
| | `stripe-checkout-client-price` | An amount, line items or price id taken from the request when creating a Checkout Session, PaymentIntent or subscription. |
| | `stripe-customer-unchecked` | A customer, subscription or payment id from the request passed to Stripe without going through the signed-in user. |
| Auth | `api-route-no-auth` | A route handler, Pages API handler or server action that reads or writes data and calls no recognised auth helper. |
| | `api-idor` | A record selected by an id from `params`/body/query with no ownership filter; an owner column set from client input. |
| Injection | `unsafe-html` | `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write` with non-constant input and no recognised sanitizer. |
| | `open-redirect` | `redirect()`, `NextResponse.redirect()`, `res.redirect()`, `router.push()` or `location` assignment with a target that comes from the request and is not validated. |
| Config | `cors-wildcard-credentials` | `Access-Control-Allow-Origin` as `*` or a reflected origin together with credentials. |
| | `no-rate-limit` | (info) An auth or webhook route with no recognisable rate limiting. |
| | `build-checks-disabled` | `typescript.ignoreBuildErrors` or `eslint.ignoreDuringBuilds` set to `true`. |
| | `security-headers` | (info) No security headers configured anywhere; (low) a weakened header. |
| | `deps-unpinned` | `*` or `latest` in `package.json`; no lockfile at the project root. |

`saas-audit --list-rules` prints the same list.

How it works, briefly:

- **TypeScript and TSX** are parsed with the TypeScript compiler API (`typescript` is the only runtime dependency). Route handlers (`app/**/route.ts`, `pages/api/**`), server actions (`"use server"` files and inline directives) and client components (`"use client"`) are recognised from the AST and the file path.
- **Taint** is tracked inside one function: parameters of an entry point, `request.json()`, `searchParams.get()`, `params`, `FormData` and values derived from them are "client-controlled". A lookup through a map or any function that is not on a short pass-through list (`Number`, `parse`, `new URL`, ...) ends the taint, which is how `PRICES[body.plan]` or `safeNextPath(next)` are accepted.
- **SQL** migrations (`supabase/migrations/*.sql`, `supabase/schema.sql`) go through a small tokenizer of my own that handles comments, quoted identifiers, `E''` strings and dollar quoting, and a statement model for `CREATE/ALTER/DROP TABLE`, `ROW LEVEL SECURITY` and `CREATE/ALTER/DROP POLICY`, applied in file-name order.
- **Git state** is read from `.gitignore` files and, when the project root contains a `.git/index` in format 2 or 3, from the list of tracked paths. `git` is never executed.

## What it does not check

This is not a penetration test, not a vulnerability scanner and not a substitute for reading the code. A report from it is a list of places to look at first.

- **Anything that runs.** Nothing is executed, no request is sent and no database is queried. RLS is judged from the SQL in your migrations, not from the policies that are live. Policies and tables made in the Supabase dashboard are invisible; with no migrations the tool says so instead of reporting nothing.
- **Anything configured outside the repository:** Supabase auth settings and redirect allow-lists, storage bucket policies, Stripe dashboard and webhook endpoints, hosting environment variables, DNS, CDN, WAF.
- **Database objects other than tables and policies:** views (`security_invoker`), `SECURITY DEFINER` functions, grants, triggers, realtime publications. `ALTER TABLE ... RENAME` is not followed.
- **Whether an auth check is correct.** A call to a recognised helper name (`getUser`, `getSession`, `auth`, `requireUser`, `withAuth`, ... plus your `authHelpers`) anywhere in the handler counts, and so does a function in the same file that calls one. Order, branches, the result being ignored and role or plan checks are not evaluated. Reading an `Authorization` header or a `*-secret` header also counts. Middleware-only protection is not credited: mark such routes in `publicRoutes` or suppress the finding.
- **Data flow across files.** An imported helper is a black box: its result is treated as server-controlled, and database access inside an imported helper is not seen (one level of same-file helpers is followed).
- **Dependency vulnerabilities.** There is no advisory database. Run `npm audit`.
- **Secrets in git history or in files with other extensions**, only the current tree is scanned. Only `.ts/.tsx/.js/.jsx/.mjs/.cjs/.mts/.cts`, `.sql`, `.env*`, `.gitignore` and `package.json` are read. CommonJS `module.exports` handlers and non-Next.js frameworks are not recognised.
- **Everything not in the rule table**: denial of service, business-logic flaws, injection into SQL strings built by hand, SSRF, file upload handling, session fixation, privacy and legal questions.

Expect both false positives (a public table flagged for `USING (true)`, a custom auth wrapper under an unknown name) and false negatives. Findings that are intentional are handled with the config file or suppression comments, and suppressed findings stay visible in the JSON and Markdown output.

## Configuration

`saas-audit.config.json` in the audited directory (or `--config`). It is plain JSON, validated strictly, and cannot load code.

| Key | Meaning |
| --- | --- |
| `ignoreRules` | Rule ids to switch off. |
| `ignorePaths` | Globs of files or directories to skip (`**/*.test.ts`, `scripts`). |
| `authHelpers` | Extra function names that count as an auth check. |
| `publicRoutes` | Globs of route files that are public on purpose (skips `api-route-no-auth`). |
| `tenantColumns` | Extra column names that mark a row owner or tenant. |
| `sanitizers` | Extra function names that count as HTML sanitizers. |
| `dataAccessRoots` | Extra identifiers that are database clients. |
| `idempotencyHelpers` | Extra function names that count as webhook de-duplication. |
| `rateLimiters` | Extra names that count as rate limiting. |

Inline suppression, in any language the tool reads (`//`, `--`, `#`, or a block comment):

```ts
// saas-audit-ignore-next-line api-route-no-auth -- public price list
export async function GET() { ... }
```

```sql
-- saas-audit-ignore-next-line supabase-policy-permissive -- plans is a public price list
create policy "plans are public" on public.plans for select to anon using (true);
```

`saas-audit-ignore-line <rule>` covers the same line and `saas-audit-ignore-file <rule>` the whole file; `all` matches every rule. Unknown rule names and directives that suppress nothing are reported as warnings so stale comments get removed.

## Examples

- [`examples/vibe-app/`](examples/vibe-app) is a deliberately flawed Next.js + Supabase + Stripe app: dashboard-created tables, "make the error go away" policies, one all-powerful client, a webhook that parses before it verifies, a client-supplied checkout amount. Files only: it is not installed or run, and it has no lockfile.
  Its `.env.local` is committed on purpose, with placeholder values, so the tool has something to find.
- [`examples/vibe-app-fixed/`](examples/vibe-app-fixed) is the same app after the fixes the findings point at. It audits with no findings and two suppressed ones, each with a reason in the source. Its `saas-audit.config.json` switches off `deps-unpinned` because the example ships no lockfile.
- [`examples/sample-report.md`](examples/sample-report.md) is `saas-audit examples/vibe-app --markdown` verbatim: summary table by severity, findings with evidence and fix, a "what was not checked" section.

`test/examples.test.ts` asserts the exact set of 34 findings (rule, file and line) for the flawed app, that the fixed app is clean with exactly the two suppressions, and that the sample report is byte-for-byte what the CLI prints. Regenerate it with `npm run sample`.

## How I would approach rescuing an AI-built SaaS

This is the method I would follow, and the order the tool is built around. It is not a description of past client work.

1. **Audit before changing anything.** Read-only first: run `saas-audit`, `npm audit` and the type checker, list every table and policy, every route and server action, every Stripe call and every environment variable. Write down which findings are real, which are intentional (a public price list) and which need a question to the owner. Fixing before understanding is how a "quick fix" turns RLS off. The deliverable of this step is a report like the sample one plus a list of questions.
2. **RLS and auth fixes.** Rotate any key that has been in a client bundle or in git first, because it is already compromised. Then enable RLS on every public table and write one policy per operation, scoped by `auth.uid()`. Replace the single all-powerful client with a user-scoped client (the user's own token, so RLS applies) and keep the service-role client in a server-only module used by webhooks and jobs. Add one auth helper and call it at the top of every handler and action, put the ownership filter in the query as well as in RLS, and take the owner id from the session instead of the body.
3. **Stripe webhook correctness.** Read the raw body, verify with `constructEvent`, answer unknown event types with 200, record `event.id` under a unique constraint before doing the work, and derive the plan or entitlement from the verified event instead of the browser redirect. On the checkout side, the client sends a plan key and the server maps it to a price and to the customer stored for the signed-in user. Replay events with the Stripe CLI, including the same event twice and an event with a broken signature.
4. **Tests that pin the fixes.** Cheap tests that would have caught the original bugs: route-handler tests with no session (expect 401), with user A reading user B's record (expect 404), and with a tampered amount; SQL tests that switch to the `authenticated` role with two different `request.jwt.claims` and assert row counts; a webhook test that posts an unsigned body, a re-serialised body and a duplicate. Turn on `tsc --noEmit` and lint in CI and remove the flags that skip them. Run `saas-audit` in CI so the findings cannot come back.
5. **Handoff.** Leave the owner able to keep it that way: a short document of the data model, the policy for each table, the list of environment variables and where each one is used, the rotated keys and when, how to run the tests and the replay, what is deliberately public (as suppression comments with reasons), and what was not reviewed. If the owner wants coding agents to keep working in the repository, give them a read-only database role and a checklist drawn from the rules above, because the mistakes in the rule table are the ones such tools make again.

## Development

Everything runs in a container; the repository has no install step on the host.

```sh
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work node:22 \
  sh -c 'npm ci --ignore-scripts && npm run typecheck && npm test && npm run build'
```

Requires Node 22.12 or newer (CI runs 22 and 24). The test suite has no network or API-key dependency. Fixtures that look like credentials are assembled from parts at run time, so the repository contains no secret-shaped literal; the example apps use obviously fake placeholders.

Dependencies are pinned exactly and installed with `--ignore-scripts` and a publish-date cutoff; see [SECURITY.md](SECURITY.md) for the dependency policy, the trust model and the reporting address.

## License

MIT. See [LICENSE](LICENSE).
