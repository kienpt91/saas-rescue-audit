# Findings export (`--findings`)

`saas-audit <dir> --findings` prints the audit as an array of records in the `findings.json` shape published by Cloudflare's open source [security-audit-skill](https://github.com/cloudflare/security-audit-skill), so tools that read that shape can read this output. This project is not affiliated with Cloudflare. The shape is re-implemented here from its public description: no code, schema file or text of that project is included, and the tests check the output with a small checker written for this repository (`test/findings-conformance.ts`), not with that project's validator.

```sh
saas-audit /audit --findings > findings.json          # exit codes are the same as for the other formats
saas-audit /audit --findings --min-severity high -o findings.json
```

`--findings` cannot be combined with `--json` or `--markdown`. `--min-severity` applies, and `--fail-on` and the exit codes work as for the other formats. A finding that the format cannot hold is not exported and is reported on stderr (see [Limits](#limits)); it never changes the exit code.

## What the tool says, and what it does not

Every finding of this tool is a static one: it read source files and ran nothing. The format has a verdict for a finding that was independently demonstrated (`confirmed`). Nothing this tool does demonstrates anything, so **it never exports `confirmed`**; the record types in `src/report/findings.ts` cannot express it, and the test oracle refuses it.

| Verdict | When | Why |
| --- | --- | --- |
| `needs_validation` | every finding that is counted | the claim comes from reading code; `blockers` start with "Static analysis only: ..." and `validation_plan.local` says how to test it (see the rule table below) |
| `rejected` | every finding that the project itself silenced: an inline `saas-audit-ignore` comment, `ignoreRules`, or `publicRoutes` in the config | the owner decided the behaviour is intended or accepted. The `reason` says whose decision it was and that the tool **did not test or disprove** the claim. The record keeps the fingerprint the finding had before it was silenced |
| `confirmed` | never | no execution, request or query backs any finding |

The tool has no other disproved or suppressed candidates, so there is no other path to `rejected`. A hostile repository can ship ignore comments; the `reason` names where the silencing came from so a reader can tell it is the audited project's own statement.

The format has no field for the tool's own rating, so `description` carries it in one sentence ("saas-audit rates this high; that is its own static rating, not a demonstrated impact") followed by the tool's suggested change. A `needs_validation` record has no severity, as the format requires.

## Record fields

| Field | Source |
| --- | --- |
| `fingerprint` | see [Fingerprints](#fingerprints) |
| `title` | the finding's title |
| `description` | the finding's explanation, its static rating and its suggested change |
| `claimed_root_cause` | one fixed sentence per rule (rule table below) |
| `trace` | `entrypoint` (where input or exposure enters, when the rule knows it) then `sink` (where the weakness is). `scope` is the finding's subject: the table and policy, the handler, the variable |
| `evidence` | the sink line first, then the entrypoint line when the rule recorded its source text: `Source line: <the line, trimmed, with credential-shaped substrings removed, cut at 180 characters>` |
| `blockers` | the static-only limit, then the rule's own reasons (rule table) |
| `validation_plan.local` / `.deployment` | per rule (rule table) |
| `reason` (rejected) | whose decision silenced the finding, and that nothing was disproved |

There is no propagation step: the tool follows taint inside one function but does not record the path, so it does not invent one. A trace has one step when the rule knows one place (a missing setting has a sink and no entrypoint) and two when it knows both. An entrypoint at the same place as the sink is not repeated.

### Where the lines come from

Every `file:line` is a position the tool already holds: the `CREATE TABLE` or `CREATE POLICY` statement of its SQL model, the handler declaration or the offending call of its TypeScript tree, the line of the key in an env file or `package.json`. Two findings used to be filed at line 1 of a file because they describe a missing thing; the export points them at the place where the thing would be added, found in the file: the line of the `dependencies` key for "No lockfile", and the declaration of the exported `next.config` object for "No security headers are configured" (`--json` and the other formats still show line 1 for those two, as before). Where a rule cannot find a better place it keeps its own line (a `package.json` written on one line has everything on line 1). A line that is not a positive integer is never exported: the finding is left out and counted.

| Rule | Subject (identity) | Entrypoint | Sink |
| --- | --- | --- | --- |
| `supabase-rls-missing` | `schema.table` | none | the `CREATE TABLE` statement |
| `supabase-policy-permissive` | `schema.table`, policy name | the `CREATE TABLE` statement (may be in another migration) | the `CREATE POLICY` statement |
| `supabase-policy-missing` | `schema.table` | none | the `CREATE TABLE` statement |
| `supabase-tenant-unscoped` | `schema.table` | none | the `CREATE TABLE` statement |
| `secret-in-client` | the variable name | for a server secret read in a client component: the `"use client"` directive | the reference, or the line of the env file or `next.config` |
| `secret-committed-env` | the env file path | none | the first line of the env file |
| `secret-hardcoded` | the kind of secret (or `High-entropy value for NAME`) | none | the line of the literal |
| `stripe-webhook-unverified` | the handler (`POST handler`) | the handler declaration | the line where the body is parsed and trusted; when there is none, the handler itself is the only step, an entrypoint |
| `stripe-webhook-parse-before-verify` | the handler | the handler declaration | the parse, re-serialise or verification call |
| `stripe-webhook-no-idempotency` | the handler | the handler declaration | the verification call |
| `stripe-webhook-unknown-event-error` | the handler's default branch | the handler declaration | the `return` or `throw` in that branch |
| `stripe-checkout-client-price` | the handler and the kind of finding | the handler declaration | the property that takes the amount or price |
| `stripe-customer-unchecked` | the handler and the Stripe call | the handler declaration | the argument that takes the id |
| `api-route-no-auth` | the handler | the handler declaration | the first database read or write in the handler |
| `api-idor` | the handler and the kind of finding | the handler declaration | the filter value or the owner column write |
| `unsafe-html` | the title (sink and kind) | none | the sink |
| `open-redirect` | the handler, or `Client code` | the handler declaration, when the redirect is in a handler | the redirect |
| `cors-wildcard-credentials` | the title | none | the header or `cors()` call |
| `no-rate-limit` | the handler | the handler declaration, as the only step | (same line) |
| `build-checks-disabled` | the title | none | the flag |
| `security-headers` | the title | none | the exported `next.config` object, or the `"next"` line in `package.json` |
| `deps-unpinned` | the package name, or `no lockfile` | none | the dependency line; for a missing lockfile, the first dependency section |

## Fingerprints

```
saas-audit/<rule>:<path>:<subject>[:<subject>...]
```

- `<path>` is the finding's file, split on `/`, each part encoded.
- A **subject** is a name the rule recorded for what the finding is about (table, policy, handler, variable); each is encoded. The Supabase rules use `schema.table` and, for a policy finding, the policy name. A rule with nothing better uses its title.
- **Encoding** works on UTF-8 bytes: letters, digits, `.`, `_` and `-` stay; every other byte, including `+`, `:`, `/` and space, becomes `+` and two lowercase hex digits (`Anyone can use tickets` is `Anyone+20can+20use+20tickets`).
- Findings with the same rule, file and subject are told apart by their order in the file and get `@2`, `@3`, ... at the end. `@` cannot occur in an encoded name, so the suffix cannot be confused with a name.

Example: `saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:public.tickets:Anyone+20can+20use+20tickets`.

The fingerprint contains no line number, time or count, so the same input gives the same fingerprints, and an edit that only moves code (a comment, a blank line, an import above) leaves them alone. They change when the rule, the file, a table, policy, handler or variable name changes, and a second finding with the same identity placed before an existing one takes its `@` suffix; both are real changes of identity. A finding keeps its fingerprint when it changes state: the same finding silenced by a comment is exported as `rejected` with the same fingerprint.

The scheme is shared with the `proof-audit` export in this family of tools, so a static finding of this tool and the database verdict on the same table or policy carry one fingerprint (the subjects of the Supabase rules are the `schema.table` and the policy name, exactly as above). Records are sorted by fingerprint, as the format asks.

## Limits

The format's readers limit an array to 1000 records and the text to 5 MiB. When an export is larger, records are taken in order of the tool's own severity, then fingerprint, until the limit is reached or the first record that does not fit (that record and every one after it are left out, so a smaller, lower-rated record is never kept in place of a larger one). Every omission is counted on stderr. A silenced (`rejected`) finding keeps the severity of the finding it was, so a silenced critical ranks above a live medium. For example:

```
findings export: 200 findings left out: beyond the 1000-record limit of the format; findings were kept in order of severity until it was reached
```

A finding is also left out, and counted, when its file name cannot be written as a repository-relative path in the format (control or format characters, a colon, a backslash, a segment ending in a dot or space, a reserved Windows name, an absolute or `..` path) or when its line is not a positive integer. An entrypoint or sink site with such a path is dropped from the trace instead, and the finding is kept. No finding is dropped without a count.

An audit that was incomplete (files skipped) still exits with code 3 when there are no findings, exactly as for the other formats; the array cannot say so, so check the exit code or use `--json` (`"complete"`).

## What is and is not redacted

The text is built from the same finding data as the other formats, so the same redaction applies: evidence lines are scrubbed of credential-shaped substrings (known key shapes, JWTs, database URL passwords, private key blocks) **before** they are cut to length, a line whose secret is visible only after decoding escapes is withheld, and at most a four-character vendor prefix is shown. A secret the patterns do not recognise is not removed. The records still contain **file paths, table, policy, handler and variable names, and source lines** from the audited project, so treat the file as sensitive.

Unlike `--json`, which keeps repository text exactly as found, the findings export also turns control characters, bidirectional overrides, zero-width and other default-ignorable characters, line separators and lone surrogates into visible escapes (`\x1b`, `\u{202e}`) in every text field, because the consumer of this format is another program that may show or process the text. Backslashes are not escaped, so a source line that really contains the text `\x1b` reads the same as one that held the control character: the escapes protect the reader, they are not a reversible encoding. File names that contain such characters cannot be written as paths and are left out. The export contains no timestamps and no absolute paths.

## The `--json` fields behind it

Findings in `--json` (and the suppressed ones) gained three optional fields that the export is built from: `subject` (the names above), `entry` and `sink` (`{ file, line, note, text? }`, present where the rule records them).

## Per-rule mapping

Each rule has one `claimed_root_cause`, its own blockers and its validation plans. They are written once, in `src/report/findings-plans.ts`, and `test/findings.test.ts` fails when a rule has no plan or a plan has no rule. The text below is that file's content.

### `supabase-rls-missing`

- Claim: A table in the public schema is created without ENABLE ROW LEVEL SECURITY, so the REST API serves its rows to the anon role.
- Blockers beyond the static-only limit: Only the migration files were read: tables and policies changed in the Supabase dashboard, and migrations that were never applied, are not reflected.
- Local validation: Run proof-audit against the migrations: it applies them to a throwaway PostgreSQL and probes the table as the anon role and as signed-in users. A read and a write as anon that return rows or succeed confirm it.
- Deployment validation: On the deployed project, select relrowsecurity from pg_class for the table, and request the table through the REST API with the anon key.

### `supabase-policy-permissive`

- Claim: A row level security policy is always true, or lets the anon role write, so it does not restrict who can read or change rows.
- Blockers beyond the static-only limit: The policy expression was folded to a constant from its SQL text; no database evaluated it. Grants, role membership and the other policies on the table were not combined by a database.
- Local validation: Run proof-audit against the migrations: it applies them to a throwaway PostgreSQL and probes the table as the anon role and as signed-in users. A cross-user or anonymous read or write that succeeds confirms it.
- Deployment validation: On the deployed project, read the policy from pg_policies and repeat the anon and cross-user requests through the REST API.

### `supabase-policy-missing`

- Claim: Row level security is enabled on a table that has no policy for client roles, so every client request is denied.
- Blockers beyond the static-only limit: Whether the table is meant to be reached only through the service role, or the application is broken, depends on code and settings outside the migrations.
- Local validation: Run proof-audit against the migrations: it applies them to a throwaway PostgreSQL and probes the table as the anon role and as signed-in users. Denied reads and writes confirm the table is closed to clients; then check whether application code reads it with a user token.
- Deployment validation: On the deployed project, list the policies of the table with pg_policies.

### `supabase-tenant-unscoped`

- Claim: A table has an owner or tenant column that none of its policies ties to the caller, so users the policies admit can reach each other's rows.
- Blockers beyond the static-only limit: Policy expressions are matched to the owner column by their SQL text; no database evaluated them as two different users.
- Local validation: Run proof-audit against the migrations: it applies them to a throwaway PostgreSQL and probes the table as the anon role and as signed-in users. Create rows for two users and read and change user B's rows as user A: success confirms it.
- Deployment validation: On the deployed project, repeat the two-user read and write through the REST API with two real sessions.

### `secret-in-client`

- Claim: A server secret is read in client-side code, or a NEXT_PUBLIC_ variable that names a secret is published in the browser bundle.
- Blockers beyond the static-only limit: Whether the value is a real secret, and which environment variables the production build sees, is not in the repository.
- Local validation: Build the app with a distinctive placeholder value for the variable in a local env file, then search the build output (.next/static) for that placeholder: a hit means the value reaches the browser.
- Deployment validation: Load the deployed site, search the downloaded scripts for the variable name or the value prefix, and rotate the secret if it is there.

### `secret-committed-env`

- Claim: An environment file is tracked by git, or not covered by .gitignore, so credentials in it are committed or will be.
- Blockers beyond the static-only limit: The git index and the .gitignore files were parsed without running git; history was not searched. Whether the file holds live credentials was not tested.
- Local validation: In the real clone, run git ls-files and git check-ignore -v on the file, and git log --all -- on its path to see whether it was ever committed.

### `secret-hardcoded`

- Claim: A credential-shaped value is written in a source or template file.
- Blockers beyond the static-only limit: The value matched a known key shape or an entropy heuristic; a placeholder, revoked or test value looks the same as a live one. The value was not tried against the service that issued it.
- Local validation: Check with the issuing provider's own tooling, from a trusted machine, whether the key is live, without pasting it into tickets or chat; rotate it if it is.

### `stripe-webhook-unverified`

- Claim: A Stripe webhook handler never verifies the Stripe-Signature header, so anyone who knows the URL can send it forged events.
- Blockers beyond the static-only limit: Verification done by an imported helper, a middleware or a proxy under a name the tool does not recognise is not followed.
- Local validation: Run the app locally and send the handler a checkout.session.completed event with no signature, then one with a forged signature (for example the Stripe CLI with the wrong signing secret): any 2xx answer or side effect confirms it.
- Deployment validation: Send the same forged request to the deployed endpoint in Stripe test mode and look for the side effect.

### `stripe-webhook-parse-before-verify`

- Claim: A Stripe webhook handler parses or re-serialises the body before verifying the signature, which either breaks verification or means the verified bytes are not the ones used.
- Blockers beyond the static-only limit: Which bytes reach the verifier depends on framework body handling that was inferred from the code, not observed.
- Local validation: Send a correctly signed test event (Stripe CLI listen and trigger) to the local handler and check that it is accepted; then send the same payload re-serialised and check that it is rejected.

### `stripe-webhook-no-idempotency`

- Claim: A verified Stripe webhook handler never reads event.id, so a redelivered event runs its side effects twice.
- Blockers beyond the static-only limit: A de-duplication step in an imported helper, a database constraint or a queue in front of the handler is not visible.
- Local validation: Deliver the same signed event twice to the local handler and check that the side effects (credits, emails, plan changes) happen once.

### `stripe-webhook-unknown-event-error`

- Claim: A Stripe webhook handler answers event types it does not handle with an error status or an exception, so Stripe retries and can disable the endpoint.
- Blockers beyond the static-only limit: Which event types the endpoint is subscribed to is configured in the Stripe dashboard, not in the repository.
- Local validation: Send a signed event of a type the handler does not handle and check that the response is 2xx.
- Deployment validation: List the events the endpoint is subscribed to in the Stripe dashboard.

### `stripe-checkout-client-price`

- Claim: The price, amount or line items of a Stripe Checkout Session or PaymentIntent come from the request, so the caller decides what it pays.
- Blockers beyond the static-only limit: Server-side validation in an imported helper, or a Stripe-side restriction on prices, is not followed.
- Local validation: In Stripe test mode, call the route with a smaller amount or a different price id than the app offers and compare the amount of the created session.

### `stripe-customer-unchecked`

- Claim: A Stripe customer, subscription or payment id from the request is passed to Stripe without being tied to the signed-in user.
- Blockers beyond the static-only limit: An ownership check in an imported helper, or one done before this function is called, is not followed.
- Local validation: In Stripe test mode, sign in as user A and call the route with user B's customer or subscription id: a response about B, or a portal session for B, confirms it.

### `api-route-no-auth`

- Claim: A route handler or server action reads or writes data without calling any recognised authentication helper.
- Blockers beyond the static-only limit: Authentication done by middleware, a wrapper or an imported helper under a name the tool does not recognise is not followed. Whether the data is meant to be public was not decided.
- Local validation: Call the route with no session cookie and no Authorization header: any data returned or changed, instead of 401 or 403, confirms it.
- Deployment validation: Repeat the unauthenticated call against the deployed URL, where middleware and platform rules also apply.

### `api-idor`

- Claim: A record is chosen by an id from the request with no ownership filter, or a row owner is set from client input.
- Blockers beyond the static-only limit: Row level security, or an ownership check in an imported helper, may already restrict the query; the tool does not know which database client it runs with.
- Local validation: Create records for two users, then as user A request user B's record id (or create a row with B's owner id): returned or changed data confirms it.

### `unsafe-html`

- Claim: Non-constant input reaches an HTML sink (dangerouslySetInnerHTML, innerHTML, insertAdjacentHTML, document.write) without a recognised sanitizer.
- Blockers beyond the static-only limit: Whether a user can control the value was not traced across files; it may be trusted content. A sanitizer under a name the tool does not recognise is not followed.
- Local validation: Render the component in a browser or a jsdom test with a harmless marker payload such as an image tag with an onerror handler that sets a flag: the flag being set confirms it.

### `open-redirect`

- Claim: A redirect target comes from the request and is not validated before the redirect.
- Blockers beyond the static-only limit: Validation in an imported helper, or an allow-list applied elsewhere, is not followed.
- Local validation: Request the route with the redirect parameter set to an absolute URL on another host, and to a protocol-relative URL: a Location header that points there confirms it.

### `cors-wildcard-credentials`

- Claim: Access-Control-Allow-Origin is a wildcard or reflects the request origin while credentials are allowed.
- Blockers beyond the static-only limit: Headers added or overwritten by middleware, the platform or a CDN are not visible.
- Local validation: Send a request with an Origin header from another site and a session cookie, and read the Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers.
- Deployment validation: Send the same request to the deployed URL, after the platform and CDN have applied their headers.

### `no-rate-limit`

- Claim: An authentication or webhook route has no recognisable rate limiting.
- Blockers beyond the static-only limit: Rate limiting by the platform, a WAF or a CDN is configured outside the repository.
- Local validation: Send a burst of requests (for example 100 within a minute) to the route on a local instance and check whether any answer is 429.
- Deployment validation: Repeat the burst against the deployed URL and check the platform's rate-limit settings.

### `build-checks-disabled`

- Claim: next build is configured to ignore TypeScript or lint errors, so they ship unnoticed.
- Blockers beyond the static-only limit: How many errors the flag hides was not measured.
- Local validation: In a clean clone, run npx tsc --noEmit and the project's lint command: the errors they list are what the flag hides.

### `security-headers`

- Claim: No security headers are configured in the project, or one is weakened.
- Blockers beyond the static-only limit: Headers added by the hosting platform, a CDN or a reverse proxy are not visible.
- Local validation: Start the app locally and read the response headers of a page (for example with curl -I).
- Deployment validation: Read the response headers of the deployed URL, where the platform and CDN may add some.

### `deps-unpinned`

- Claim: A dependency is declared as * or latest, or the project has no lockfile, so installs are not reproducible.
- Blockers beyond the static-only limit: The versions actually resolved today were not looked up; the tool does not use the network.
- Local validation: Install twice in clean containers at different times, or run npm install --package-lock-only, and compare the resolved versions of the unpinned packages.

