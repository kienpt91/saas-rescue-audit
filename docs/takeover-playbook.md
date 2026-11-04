# Takeover playbook: the first five working days

This is the order I would follow when I inherit a Next.js + Supabase + Node codebase that an agency or a coding agent built and that now has paying users: a stabilise-first plan, not a rewrite. It is a method, not a description of past client work. It is written around what `saas-audit` actually checks (22 rules, see the [README](../README.md#what-it-checks)) and says plainly where a person has to look instead. Background jobs (a queue, Trigger.dev or similar) are covered by the checklists but not by the tool.

The day-1 output of the tool for a project of this kind is in [sample-report.md](sample-report.md), produced by `scripts/make-sample-report.sh` from a throwaway project (a made-up membership app with placeholder values only).

## What is automated and what is not

| Question | `saas-audit` | By hand in this playbook |
| --- | --- | --- |
| Tables without RLS, always-true policies, policies that ignore the owner column, RLS on with no policy | yes, from the SQL in `supabase/migrations` | compare with the live database (day 2 and day 4): tables and policies made in the dashboard are invisible to the tool |
| Views, `SECURITY DEFINER` functions, grants, storage policies | no | catalog queries on day 4 |
| Server secrets in client code, `NEXT_PUBLIC_` secrets, `.env` files that git would take, key-shaped literals | yes, in the current tree | git history, the hosting environment and third-party dashboards (day 1) |
| Stripe webhook verification, parse-before-verify, idempotency, unknown-event handling, client-supplied price and customer ids | yes | whether the *business logic* after the event is right: entitlement, proration, failed-payment grace (day 4) |
| Routes and server actions with no recognised auth helper; ids taken from the request without an owner filter | yes, by helper name and within one function | whether each check is correct and complete |
| Unsafe HTML, open redirects, wildcard CORS with credentials, missing rate limiting and security headers, unpinned dependencies, build checks switched off | yes | |
| Known vulnerabilities in dependencies | no (no advisory database) | `npm audit` and a lockfile review (day 3) |
| Background jobs, cron, queue workers | no | day 4 checklist |
| Anything that runs: behaviour of live policies, real requests | no | a database-level probe such as the author's `proof-audit` for RLS, plus manual replay of webhooks |

Every finding is a candidate with evidence, not proof. Triage each one as **real**, **intentional** (a public price list) or **needs a question to the owner**; do not fix before you know which.

## Before day 1: terms of the first week

- Read-only first. No change to production in week one except rotating a secret that is already exposed.
- A written list of questions to the owner (who pays for what, which users are real, what must never go down), answered by day 5.
- Agree where credentials are shared: a password manager or a secrets vault, never chat, e-mail or a ticket. Grant the least access that works: a read-only role on the database, viewer on hosting and on Stripe.
- A fresh backup of the production database exists and a restore has been tried once, before anyone changes a policy or a migration.

## Day 1: access and secrets inventory

Goal: know who and what can reach production, and rotate what has leaked.

1. **Inventory every system**, one row each: owner of the account, who has access, where the credentials live, whether test and live are separate.
   - Git hosting (organisation owners, deploy keys, third-party apps, branch protection)
   - Hosting (project, team members, environment variables per environment, preview deployments that share production variables)
   - Supabase (organisation and project members, API keys, JWT secret, database password, auth providers, redirect allow-list, storage buckets)
   - Stripe (live and test, restricted keys versus the full secret key, webhook endpoints and the events they subscribe to, the signing secret of each)
   - Background jobs or queue provider, e-mail provider, LLM provider keys, error tracker, analytics, domain registrar and DNS
2. **List every environment variable** the code reads and mark which side uses it (server, browser, job). Compare with what is set on the host. `saas-audit` flags a `NEXT_PUBLIC_` name that contains a secret marker and a server secret read in a `"use client"` file; it cannot see what is set on the host.
3. **Search for committed secrets.** `saas-audit` covers the current tree (`secret-committed-env`, `secret-hardcoded`, `secret-in-client`). It does not read git history: scan the history with a dedicated scanner as well.
4. **Rotate in this order**: anything found in the browser bundle or in git history; then keys held by people who are leaving; then the rest on a schedule. A key that was ever public is compromised even after it is removed. Note when each was rotated.
5. Remove access that nobody can justify. Turn on two-factor authentication for every account in the inventory.

End of day: the inventory table, a list of rotated keys and a list of questions.

## Day 2: run it locally and establish the baseline

Goal: a clean machine can run the project, and you know what is already broken.

1. Fresh clone, the Node version from `engines` or the host, `npm ci --ignore-scripts` in a container if you do not trust the dependencies yet. Document every step that was not written down.
2. Local Supabase from the migrations (`supabase start`, then `supabase db reset`). If it fails, the migrations do not describe production: the first gap in your map. Compare the live schema with the migrations (`supabase db diff` against the linked project). Tables and policies that exist only in the dashboard are invisible to `saas-audit`.
3. Record the baseline of the project's own checks: type check, lint, tests, build. Write down what fails and what is skipped. `build-checks-disabled` flags `typescript.ignoreBuildErrors` and `eslint.ignoreDuringBuilds`; switching them back on is a day-5 backlog item, not something to do before you know how many errors appear.
4. Run the auditor, from a container with no network and read-only mounts (commands in the README):

   ```sh
   node dist/cli.js /audit --markdown --output /out/report.md
   ```

   Keep the report as the day-2 baseline. Add `--json` if you want to track it.
5. Triage the findings into the three groups above. Write one line per finding. For the intentional ones, add an inline suppression comment with a reason or an entry in `saas-audit.config.json`; both stay listed in the report.

End of day: a working local setup, the baseline and the triaged findings.

## Day 3: observability and the dependency sweep

Goal: stop flying blind, then know what you are standing on.

1. **Observability before fixes.** An error tracker on server and browser, request logs that include a request id, and an alert on every webhook and job failure. Stripe's dashboard shows webhook delivery attempts and failures; the database shows slow queries. Without these you cannot tell whether a later fix helped.
2. **Money and auth events get structured logs**: the Stripe event id, the user id, the outcome. Never log tokens, card data or full request bodies.
3. **Dependencies.** `npm audit` (the tool has no advisory database), `npm outdated`, a lockfile that is committed, and exact versions for what matters. The tool's `deps-unpinned` rule reports `*` or `latest` and a missing lockfile, nothing more. Check for abandoned packages and for anything installed by an install script.
4. **Platform checks.** Supabase's security and performance advisors, if you have project access; the hosting provider's build and runtime logs.
5. A health check and an uptime monitor on the pages and webhooks that pay the bills.

End of day: dashboards and alerts exist; a dependency list with the known problems and what each would take.

## Day 4: the payment path and the RLS review

Goal: confirm money and data cannot go to the wrong place.

**Payment path**, from click to entitlement:

1. Checkout: the server maps a plan key to a price id; the browser cannot send an amount or a customer id (`stripe-checkout-client-price`, `stripe-customer-unchecked`).
2. Webhook: raw body, signature verified before parsing, the event id recorded under a unique constraint before work is done, unknown event types answered with 200 (`stripe-webhook-unverified`, `stripe-webhook-parse-before-verify`, `stripe-webhook-no-idempotency`, `stripe-webhook-unknown-event-error`).
3. Entitlement comes from the verified event, not from the browser redirect, and can be re-derived from Stripe if the webhook was missed.
4. By hand, because the tool cannot see them: failed-payment grace and dunning, cancellation at period end, plan changes and proration, the customer portal configuration, tax, test versus live keys in each environment. Replay events with the Stripe CLI, including the same event twice and one with a broken signature.
5. Background jobs and cron: which key do they use (a service-role key bypasses RLS), are they idempotent, what happens on retry, who is alerted when one fails.

**RLS and access control:**

1. Take every `supabase-*` finding and every route finding from the baseline and confirm each against the live database, not only the migrations.
2. Run the catalog queries the tool cannot replace, against the live database with a read-only role:

   ```sql
   -- tables in public with row level security off
   select tablename from pg_tables where schemaname = 'public' and not rowsecurity;

   -- every policy, to compare with the migrations
   select schemaname, tablename, policyname, cmd, roles, qual, with_check from pg_policies where schemaname in ('public', 'storage');

   -- views over protected tables (check reloptions for security_invoker=true)
   select c.relname, c.reloptions from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'v';

   -- SECURITY DEFINER functions, and who may execute them
   select p.proname, p.proconfig, p.proacl from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prosecdef;

   -- what anon and authenticated may do to tables
   select grantee, table_name, privilege_type from information_schema.role_table_grants where table_schema = 'public' and grantee in ('anon', 'authenticated');
   ```

   `saas-audit` does not model any of these objects; the storage policies in particular are only visible here and in the dashboard.
3. For a database-level proof, run a probe tool against a throwaway copy of the migrations: two synthetic users and an anonymous caller attempt the reads and writes and the answers are recorded. This tool does not do that; `proof-audit` is the author's separate project for it.
4. Check that the browser uses only the anon key, that server code uses a client scoped to the user's token wherever RLS is supposed to apply, and that the service-role client lives in one server-only module.

End of day: every high or critical finding is confirmed, refuted or turned into a question.

## Day 5: the prioritised stabilisation backlog

Goal: a written plan the owner can agree to, and a first task to start on.

Order by **blast radius × ease of exploitation**, not by the tool's order:

| Priority | Meaning | Typical contents |
| --- | --- | --- |
| P0, this week | Data or money can leave now | a table with no RLS or an always-true policy; a route that writes with no auth; a secret in the browser bundle; an unverified webhook; client-chosen price |
| P1, next two weeks | Wrong behaviour that costs real money or support time | webhook idempotency, failed-payment handling, an ownership filter missing on an id lookup, jobs that retry unsafely |
| P2, month one | Makes the next change safe | tests that pin each P0 and P1 fix, CI running type check, lint, tests and `saas-audit`, build checks switched back on, a lockfile and exact versions |
| P3, later | Hardening and clean-up | rate limiting, security headers, CORS, structure, docs, upgrades |

Each item gets: the finding id or question that produced it, the fix in one sentence, the test that proves it (for example: a route test with no session expects 401; user A requesting user B's record expects 404; a duplicate webhook is processed once), the risk of the change and a rollback.

Handoff documents to leave behind: data model and the policy for each table, the environment-variable list with where each is used, the rotation log, how to run the tests and the webhook replay, what is deliberately public (as suppression comments with reasons) and what was not reviewed.

### Sample backlog from the sample report

From [sample-report.md](sample-report.md) (a made-up app; the ids are those of the committed report), in the order I would take them:

| Priority | Findings | First step |
| --- | --- | --- |
| P0 | SA-002 (`credit_ledger` has no RLS), SA-007 and SA-009 (any signed-in user can read and write every row of `generations`), SA-008 (anyone can read every row of `members`), SA-001 and SA-004 (`generate` route has no auth and takes the owner from the body) | enable RLS and owner-scoped policies in a migration; take the user id from the session; add the tests that fail before the change |
| P0 | SA-005 (server secret read in a client component), SA-003 (portal session for a customer id from the request) | remove the client read and rotate the key; look the customer up from the signed-in user |
| P1 | SA-011 (read by id only), SA-012 (webhook does not deduplicate), SA-015 (unknown events answer 500), SA-006 (unsanitised HTML), SA-010 (`.env.local` not ignored by git), SA-014 (`waitlist` has RLS but no policy, so nobody can use it) | add the ownership filter; record `event.id`; answer 200; sanitise or drop the HTML; ignore the file and rotate what it held; decide the intended access and write the policy |
| P2 | SA-013, SA-016, SA-017 (build errors ignored, no lockfile, `latest`) | add the lockfile and exact versions, then switch type checking back on and fix what appears |
| P3 | SA-018, SA-019 | rate limiting and security headers |

## The paid test task

Before a larger engagement I would suggest one small, paid, written task, instead of an unpaid trial:

- **Scope**: one P0 or P1 item from the backlog, chosen together, small enough for about a day. The webhook (verify, deduplicate, test with a replayed event and a bad signature) or one table's RLS with the tests that prove it are good candidates.
- **Deliverable**: a pull request against a branch, with tests that fail before the change and pass after, a short note on the risk and the rollback, and no unrelated changes.
- **Acceptance** is written before the work starts: which tests, which commands, which behaviour. Review is by the owner or their developer; they keep the code whether or not we continue.
- **Fixed price, paid** whatever the outcome of the larger engagement. It shows how I work and communicate, and how the owner reviews, with little risk on either side.

## Limits of this playbook

It is a plan and a set of checks, not a guarantee. The tool reads source and SQL in a repository; it is a set of heuristics with false positives and false negatives (see [What it does not check](../README.md#what-it-does-not-check)). Findings need human confirmation, and a clean report does not mean the application is secure.
