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

Nothing here needs to be installed on your machine. These commands use the official Node image, pinned by digest (Node 22.22; the `node:22` tag moves, so re-pin when you update). The project is not published to a registry.

```sh
IMAGE=node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752

# 1. install exactly what the lockfile says (no install scripts) and compile
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work $IMAGE \
  sh -c 'npm ci --ignore-scripts && npm run build'

# 2. audit a directory: both mounts are read-only and the container has no network
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD":/work:ro -v /path/to/your/app:/audit:ro -w /work $IMAGE \
  node dist/cli.js /audit
```

Add `--json`, `--markdown` or `--findings` for the other formats, and `--output <file>` to write a file (the output directory then has to be mounted writable).

```
saas-audit [dir] [options]
  --json                  JSON report
  --markdown              Markdown report in client-deliverable format
  --findings              findings.json records (Cloudflare security-audit-skill shape)
  -o, --output <file>     write the report to a file
  --config <file>         config file (default: <dir>/saas-audit.config.json)
  --min-severity <level>  hide findings below critical|high|medium|low|info
  --fail-on <level|none>  exit 1 at or above this level (default: low)
  --allow-incomplete      do not use exit code 3 when files were skipped or could not be analysed
  --date <YYYY-MM-DD>     print a date in the Markdown header (off by default, so output is reproducible)
  --no-color, --list-rules, --help, --version
```

Exit codes, so it can gate a CI job: `0` nothing at or above `--fail-on` (default `low`) and the audit is complete; `1` findings; `2` usage, input or internal error; `3` the audit is **incomplete** (a file was skipped because of a limit or could not be read) and there are no findings to report. A skipped file is never a silent pass: it is listed under "Not analysed" in every format, `--json` has `"complete": false`, and the exit code is non-zero unless you pass `--allow-incomplete`.

## What it checks

Twenty-two rules in six families. Each one has positive and negative tests in `test/`.

| Family | Rule | What it reports |
| --- | --- | --- |
| Supabase RLS | `supabase-rls-missing` | A table created in a public-schema migration that never gets `ENABLE ROW LEVEL SECURITY` (critical when it has an owner column, otherwise high). |
| | `supabase-policy-permissive` | A policy whose `USING` or `WITH CHECK` is always true (`true`, `1 = 1`, `true or x`, `not false`, `'x' = 'x'`, ...); any write policy that names the `anon` role; a policy too deeply nested to fold. |
| | `supabase-policy-missing` | RLS is on but no policy exists for client roles. |
| | `supabase-tenant-unscoped` | The table has an owner or tenant column (`user_id`, `org_id`, ..., or any column that references `auth.users`) and no policy ties it to the caller: compares it with `auth.uid()`/`auth.jwt()`/`current_setting()` or passes it to a function such as `is_member(org_id)`. Merely mentioning it (`user_id is not null`) does not count. |
| Secrets | `secret-in-client` | A server secret read in a `"use client"` file; a `NEXT_PUBLIC_*` name that contains `SERVICE_ROLE`, `SECRET`, `PRIVATE`, `PASSWORD`, ... in code, `.env` files or the `next.config` `env` block. |
| | `secret-committed-env` | An `.env*` file that is in the git index or not covered by `.gitignore`. |
| | `secret-hardcoded` | Known key shapes (Stripe, AWS, GitHub, Slack, JWTs with `role: service_role`, private key blocks, database URLs with passwords) and high-entropy literals assigned to secret-looking names. |
| Stripe | `stripe-webhook-unverified` | A webhook handler with no reachable `<x>.webhooks.constructEvent` call (or `constructEventAsync`, or a helper named in `authHelpers`). A function that merely has that name, one that is never called, and a call inside `if (false)` do not count. |
| | `stripe-webhook-parse-before-verify` | The body is parsed as JSON (or re-serialised) before verification, or `req.body` is used without `bodyParser: false`. |
| | `stripe-webhook-no-idempotency` | A verified handler that never reads `event.id`. |
| | `stripe-webhook-unknown-event-error` | The `default` branch or final `else` for event types returns a 4xx/5xx or throws. |
| | `stripe-checkout-client-price` | An amount, line items or price id taken from the request when creating a Checkout Session, PaymentIntent or subscription. |
| | `stripe-customer-unchecked` | A customer, subscription or payment id from the request passed to Stripe without going through the signed-in user. |
| Auth | `api-route-no-auth` | A route handler, Pages API handler or server action that reads or writes data and calls no recognised auth helper. |
| | `api-idor` | A record selected by an id from `params`/body/query with no ownership filter; an owner column set from client input. |
| Injection | `unsafe-html` | `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write` with non-constant input and no recognised sanitizer. |
| | `open-redirect` | `redirect()`, `NextResponse.redirect()`, `res.redirect()`, `router.push()` or `location` assignment with a target that comes from the request and is not validated before the redirect (a check whose result is not used as a condition, or that comes after the redirect, does not count). |
| Config | `cors-wildcard-credentials` | `Access-Control-Allow-Origin` as `*` or a reflected origin together with credentials. |
| | `no-rate-limit` | (info) An auth or webhook route with no recognisable rate limiting. |
| | `build-checks-disabled` | `typescript.ignoreBuildErrors` or `eslint.ignoreDuringBuilds` set to `true`. |
| | `security-headers` | (info) No security headers configured anywhere; (low) a weakened header. |
| | `deps-unpinned` | `*` or `latest` in `package.json`; no lockfile at the project root. |

`saas-audit --list-rules` prints the same list.

How it works, briefly:

- **TypeScript and TSX** are parsed with the TypeScript compiler API (`typescript` is the only runtime dependency). Route handlers (`app/**/route.ts`, `pages/api/**`), server actions (`"use server"` files and inline directives) and client components (`"use client"`) are recognised from the AST and the file path.
- **Taint** is tracked inside one function: parameters of an entry point, `request.json()`, `searchParams.get()`, `params`, `FormData` and values derived from them are "client-controlled". A lookup through a map or any function that is not on a short pass-through list (`Number`, `parse`, `new URL`, ...) ends the taint, which is how `PRICES[body.plan]` or `safeNextPath(next)` are accepted.
- **SQL** migrations (`supabase/migrations/*.sql`, `supabase/schema.sql`) go through a small tokenizer of my own that handles comments, quoted identifiers, `E''` strings and dollar quoting, and a statement model for `CREATE/ALTER/DROP TABLE`, `ROW LEVEL SECURITY` and `CREATE/ALTER/DROP POLICY`, applied in file-name order. Identifiers follow PostgreSQL: unquoted names fold to lower case, quoted names keep their case. Policy expressions are folded as boolean constants.
- **Git state** is read from `.gitignore` files and, when the project root contains a `.git/index` in format 2 or 3, from the list of tracked paths. `git` is never executed.

## What it does not check

This is not a penetration test, not a vulnerability scanner and not a substitute for reading the code. A report from it is a list of places to look at first.

- **Anything that runs.** Nothing is executed, no request is sent and no database is queried. RLS is judged from the SQL in your migrations, not from the policies that are live. Policies and tables made in the Supabase dashboard are invisible; with no migrations the tool says so instead of reporting nothing.
- **Anything configured outside the repository:** Supabase auth settings and redirect allow-lists, storage bucket policies, Stripe dashboard and webhook endpoints, hosting environment variables, DNS, CDN, WAF.
- **Database objects other than tables and policies:** views (`security_invoker`), `SECURITY DEFINER` functions, grants, triggers, realtime publications. `ALTER TABLE ... RENAME` is not followed. Policies or RLS statements inside `DO` blocks, functions or `EXECUTE` are not interpreted (a warning says where they are).
- **Whether an auth check is correct.** A call to a recognised helper name (`getUser`, `getSession`, `auth`, `requireUser`, `withAuth`, ... plus your `authHelpers`) anywhere in the handler counts, and so does a function in the same file that calls one. Order, branches, the result being ignored and role or plan checks are not evaluated. Reading an `Authorization` header or a `*-secret` header also counts. The same trust in names applies to `authHelpers` as webhook verifiers, sanitizers and rate limiters you name in the config. Middleware-only protection is not credited: mark such routes in `publicRoutes` or suppress the finding.
- **Data flow across files.** An imported helper is a black box: its result is treated as server-controlled, and database access inside an imported helper is not seen (one level of same-file helpers is followed).
- **Dependency vulnerabilities.** There is no advisory database. Run `npm audit`.
- **Secrets in git history or in files with other extensions**, only the current tree is scanned. A secret split across string concatenations or assembled at run time is not recognised. Only `.ts/.tsx/.js/.jsx/.mjs/.cjs/.mts/.cts`, `.sql`, `.env*`, `.gitignore` and `package.json` are read. CommonJS `module.exports` handlers and non-Next.js frameworks are not recognised.
- **Everything not in the rule table**: denial of service, business-logic flaws, injection into SQL strings built by hand, SSRF, file upload handling, session fixation, privacy and legal questions.

Expect both false positives (a public table flagged for an always-true policy, a custom auth wrapper under an unknown name) and false negatives. Findings that are intentional are handled with the config file or suppression comments; both stay visible in the reports (see below).

## Auditing a repository you do not trust

The auditor is meant to be pointed at code that arrives from someone else, so it treats everything in the project directory as hostile input. It never executes project code or `git`, never uses the network, and:

- **Reads only regular files, without following symlinks.** Files are opened with `O_NOFOLLOW` and `O_NONBLOCK` and checked on the open descriptor, so a FIFO, a device or a symlink swapped in after the directory listing cannot hang or redirect the run. The config file found in the audited directory gets the same treatment (a symlink there is refused, not read). A path you pass with `--config` is your own choice and may be a symlink. A `.git` that is a symlink or a file is not trusted.
- **Bounds work.** Limits: 1 MiB per file, 20 000 files and 64 MiB in total, 64 directory levels, a syntax tree no deeper than 1 000 levels, 10 s per file and rule and 120 s overall. Glob patterns (config and `.gitignore`) are matched without regular expressions and are limited to 256 characters and 16 wildcards; the secret-shape patterns have bounded quantifiers. Measured before and after the hardening, on inputs built to be worst cases: a 128 KiB string of repeated `postgres://x:` went from 1 044 ms to 6 ms and a `-eyJ…` string from 1 395 ms to 5 ms; a 40 000-deep parenthesised policy from 4 113 ms to 2 ms; a 30-character name against a glob with 17 wildcards from 13 393 ms (patterns with more than 16 wildcards are now rejected, and the largest one still allowed takes under 1 ms); 2 000 exported server actions in one file from 10 972 ms to 119 ms; 20 000 policies in one migration from 17 552 ms to 120 ms; a line with 80 000 spaces in an `.env` file from 8 862 ms to under 1 ms. Deeply nested code (`((((…))))`, long `a+a+a…` chains) used to crash the run with a stack overflow; it is now skipped with a message.
- **Reports what it did not cover.** A file that is too large, unreadable, too deep, out of time or beyond the file limits is listed under "Not analysed", and the exit code is 3 (see above). Directories skipped by name, paths excluded by `ignorePaths`, rules switched off by `ignoreRules`, routes marked in `publicRoutes` and extra helper names from the config are printed in every format under "Configuration in effect", and the findings they silenced are listed under "not counted" with what silenced them. `node_modules`, `.git`, `.next`, `.turbo`, `.vercel` and `.cache` are skipped at any depth; `dist`, `build`, `out` and `coverage` only next to a `package.json`, so a route segment called `build` is still audited.
- **Does not repeat secrets.** Evidence is the source line with credential-shaped substrings removed before it is cut to length (`sk_l…[36 chars]`, `[private key block, 118 chars]`, `[database password, 16 chars]`, `[JWT withheld]`). Evidence for a hard-coded secret is built from the match, not from the line. A line whose secret is only visible after decoding `\x…`/`\u…` escapes is withheld as a whole. Only the vendor prefix of a key with one (four characters) is ever shown. A secret the patterns do not recognise is not removed from the line of another finding.
- **Does not let repository text act on your terminal or your documents.** File names, policy names, source lines, the package name and warnings come from the repository. In the terminal report every control character, escape sequence, bidirectional override and zero-width character becomes a visible escape (`\x1b`, `\u{202e}`). In the Markdown report the same text is escaped so that backticks, pipes, brackets, HTML, links, `@mentions`, `$` math and newlines cannot form markup; locations are code spans with delimiters longer than any backtick run inside, and evidence fences are longer than any backtick run in the evidence. The JSON report keeps the text exactly as found (JSON escapes control characters itself), so a program that renders it has to sanitize it for its own output.
- **Quotes suggested shell commands.** The `git rm --cached` and `npm install` hints put names through POSIX quoting.

## Configuration

`saas-audit.config.json` in the audited directory (or `--config`). It is plain JSON, validated strictly, and cannot load code. Because it ships with the repository you are auditing, treat a config that comes from the repository as part of what you are reviewing: what it excludes is printed at the top of every report.

| Key | Meaning |
| --- | --- |
| `ignoreRules` | Rule ids to switch off. Their findings are listed as not counted. |
| `ignorePaths` | Globs of files or directories to skip (`**/*.test.ts`, `scripts`). The number of paths excluded is reported. |
| `authHelpers` | Extra function names that count as an auth check, and as webhook signature verification. |
| `publicRoutes` | Globs of route files that are public on purpose (`api-route-no-auth` is listed as not counted). |
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

`saas-audit-ignore-line <rule>` covers the same line and `saas-audit-ignore-file <rule>` the whole file; `all` matches every rule. Unknown rule names and directives that suppress nothing are reported as warnings so stale comments get removed. Every finding silenced by a comment or by the config is listed in the terminal, Markdown and JSON reports with what silenced it.

## Findings export

`--findings` prints the same audit as an array of records in the `findings.json` shape published by Cloudflare's open source [security-audit-skill](https://github.com/cloudflare/security-audit-skill), so the output can be read by tools that expect that shape. It is optional and changes nothing else; this project is not affiliated with Cloudflare, and the shape is re-implemented from its public description (no code or schema file of that project is included).

```sh
saas-audit /audit --findings --output findings.json
```

What it says is limited to what the tool did:

- Every counted finding is a **`needs_validation`** record. Nothing this tool does runs code or sends a request, so it never exports `confirmed`. The blockers start with "Static analysis only", and `validation_plan.local` says how to test the claim for that rule (for example "run proof-audit against the migrations" for the RLS rules, "send a forged signature to a local handler" for the webhook rules). The rule table in [docs/findings-export.md](docs/findings-export.md) lists the claim, blockers and plans per rule.
- A finding the project silenced itself (an ignore comment, `ignoreRules`, `publicRoutes`) is a **`rejected`** record whose reason says it was the project's decision and that the tool did not test or disprove it. It keeps the fingerprint it had before. Here `rejected` means "silenced by the project, not refuted", so a consumer that hides rejected records by default will hide findings the project chose to silence.
- The `fingerprint` is `saas-audit/<rule>:<path>:<subject>`, built from the rule, the file and the table, policy, handler or variable name, never from a line number or a time: the same input gives the same fingerprints and an edit that only moves code does not change them.
- `trace` has an entrypoint (the handler or table) and a sink where the rule records both, and `evidence` quotes the source line. Every `file:line` is a position the tool already holds.
- The format's own limits (1000 records, 5 MiB, repository-relative paths) are respected: anything left out is counted on stderr.
- The records contain file paths, names and source lines from the audited project. Credential-shaped substrings are removed from the quoted lines as in the other formats, and control and bidirectional characters are escaped; see [docs/findings-export.md](docs/findings-export.md) and [SECURITY.md](SECURITY.md) for exactly what is and is not redacted.

## Examples

- [`examples/vibe-app/`](examples/vibe-app) is a deliberately flawed Next.js + Supabase + Stripe app: dashboard-created tables, "make the error go away" policies, one all-powerful client, a webhook that parses before it verifies, a client-supplied checkout amount. Files only: it is not installed or run, and it has no lockfile.
  Its `.env.local` is committed on purpose, with placeholder values, so the tool has something to find.
- [`examples/vibe-app-fixed/`](examples/vibe-app-fixed) is the same app after the fixes the findings point at. It audits with no findings and three not counted: two silenced by inline comments with a reason, one by its `saas-audit.config.json`, which switches off `deps-unpinned` because the example ships no lockfile.
- [`examples/sample-report.md`](examples/sample-report.md) is `saas-audit examples/vibe-app --markdown` verbatim: summary table by severity, findings with evidence and fix, a "what was not checked" section.
- [`examples/sample-findings.json`](examples/sample-findings.json) is `saas-audit examples/vibe-app --findings` verbatim: 34 `needs_validation` records.
- [`docs/sample-report.md`](docs/sample-report.md) is the Markdown report for a different, made-up project that looks like an inherited membership app. It is generated by `scripts/make-sample-report.sh`, which writes the project, builds the tool and runs it in containers, and keeps the tool's output unedited.

`test/examples.test.ts` asserts the exact set of 34 findings (rule, file and line) for the flawed app, that the fixed app is clean with exactly those three not counted, and that the sample report is byte-for-byte what the CLI prints. Regenerate it with `npm run sample` (and the findings file with `npm run sample:findings`).

## How I would approach rescuing an AI-built SaaS

This is the method I would follow, and the order the tool is built around. It is not a description of past client work.

The five-day version, with the access checklist, the catalog queries for what the tool cannot see, a backlog built from the sample report and the paid test-task approach, is in [docs/takeover-playbook.md](docs/takeover-playbook.md).

1. **Audit before changing anything.** Read-only first: run `saas-audit`, `npm audit` and the type checker, list every table and policy, every route and server action, every Stripe call and every environment variable. Write down which findings are real, which are intentional (a public price list) and which need a question to the owner. Fixing before understanding is how a "quick fix" turns RLS off. The deliverable of this step is a report like the sample one plus a list of questions.
2. **RLS and auth fixes.** Rotate any key that has been in a client bundle or in git first, because it is already compromised. Then enable RLS on every public table and write one policy per operation, scoped by `auth.uid()`. Replace the single all-powerful client with a user-scoped client (the user's own token, so RLS applies) and keep the service-role client in a server-only module used by webhooks and jobs. Add one auth helper and call it at the top of every handler and action, put the ownership filter in the query as well as in RLS, and take the owner id from the session instead of the body.
3. **Stripe webhook correctness.** Read the raw body, verify with `constructEvent`, answer unknown event types with 200, record `event.id` under a unique constraint before doing the work, and derive the plan or entitlement from the verified event instead of the browser redirect. On the checkout side, the client sends a plan key and the server maps it to a price and to the customer stored for the signed-in user. Replay events with the Stripe CLI, including the same event twice and an event with a broken signature.
4. **Tests that pin the fixes.** Cheap tests that would have caught the original bugs: route-handler tests with no session (expect 401), with user A reading user B's record (expect 404), and with a tampered amount; SQL tests that switch to the `authenticated` role with two different `request.jwt.claims` and assert row counts; a webhook test that posts an unsigned body, a re-serialised body and a duplicate. Turn on `tsc --noEmit` and lint in CI and remove the flags that skip them. Run `saas-audit` in CI so the findings cannot come back.
5. **Handoff.** Leave the owner able to keep it that way: a short document of the data model, the policy for each table, the list of environment variables and where each one is used, the rotated keys and when, how to run the tests and the replay, what is deliberately public (as suppression comments with reasons), and what was not reviewed. If the owner wants coding agents to keep working in the repository, give them a read-only database role and a checklist drawn from the rules above, because the mistakes in the rule table are the ones such tools make again.

## Development

Everything runs in a container; the repository has no install step on the host.

```sh
IMAGE=node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work $IMAGE \
  sh -c 'npm ci --ignore-scripts && npm run typecheck && npm test && npm run build'
```

Requires Node 22.12 or newer (CI runs 22 and 24). The test suite has no network or API-key dependency. Fixtures that look like credentials, and every hostile fixture (escape sequences in file names, backtick-laden evidence, symlinks to `/dev/zero`, FIFOs, deeply nested code, worst-case glob and regex inputs), are built at run time, so the repository contains no secret-shaped literal; the example apps use obviously fake placeholders.

Dependencies are pinned exactly and installed with `--ignore-scripts` and a publish-date cutoff; see [SECURITY.md](SECURITY.md) for the dependency policy, the trust model and the reporting address.

### Tests and coverage

`npm test` runs 484 tests in 18 files, all offline; `npm run coverage` runs them with V8 coverage and fails below the thresholds in `vitest.config.ts`. The numbers below are from one run in the container above (Node 22.22), after the findings export was added:

| Scope | Statements | Branches | Functions | Lines |
| --- | --- | --- | --- | --- |
| all of `src` | 94.45% | 87.20% | 97.82% | 97.69% |
| `src/report` (the report renderers and the findings export) | 100% | 94.32% | 100% | 100% |
| `src/report/findings.ts` | 100% | 92.92% | 100% | 100% |
| `src/ts` (TypeScript taint and call analysis, the lowest) | 86.96% | 77.35% | 92.72% | 92.51% |

The findings export has 113 of those tests (`test/findings.test.ts`): a conformance check written for this repository and tested against deliberately broken records; the fingerprint encoding and its stability under a second run, lines added above the code, an ignore comment and a moved handler; every rule's plan against the catalog and against `docs/findings-export.md`; hostile and odd input (unknown rules, invisible or control-character text, lone surrogates, bad lines and file names, more than 1000 records, more than 5 MiB); 300 generated projects with names built from awkward characters, each checked for conformance, repeatability, line-shift stability and for losing no finding without counting it; and the command line.

## Secrets and hooks

Never commit `.env` files or credentials. Keep real values in an untracked `.env` and document the variable names in `.env.example` with placeholders only.

Install [lefthook](https://github.com/evilmartians/lefthook) and run `lefthook install` once per clone. This enables two hooks:

- `pre-commit` scans the staged changes (`sh scripts/secret-scan.sh --staged`).
- `pre-push` scans the whole tree (`sh scripts/secret-scan.sh --tree`).

CI also runs the tree scan and a full-history scan (`--history`). The scanner is a dependency-free POSIX shell script that looks for forbidden file names (such as `.env` or private key files) and for key-shaped values, and it never prints the matched value. A reviewed false positive can be allowed in `.secret-scan-allow` with one line per file and rule, `<path> <rule>   # reason`, or on a single line with the marker `secret-scan: allow`.

If a secret is ever committed, rotate it first, treating it as compromised, and only then remove it from history.

## Releasing

Releases are cut by pushing a `vMAJOR.MINOR.PATCH` tag. The `release` workflow then verifies the code, builds the files, writes `SHA256SUMS`, attests where they were built and creates the GitHub release. See [RELEASING.md](RELEASING.md) for how to cut a release and how to verify a download with `gh attestation verify`.

## License

MIT. See [LICENSE](LICENSE).
