#!/bin/sh
# Generate docs/sample-report.md: the Markdown report of saas-audit for a throwaway project that looks like an
# inherited, agency-built Next.js + Supabase + Stripe membership app.
#
# The project is written to out/sample-project by this script (so there is nothing secret-shaped in the repository
# and nothing to keep in sync), the tool is built and run in containers, and the report is the tool's stdout,
# unedited. The audit container has no network and mounts both the tool and the project read-only. Every value
# in the project is a made-up placeholder; no real application is involved.
#
# usage: scripts/make-sample-report.sh
set -eu
cd "$(dirname "$0")/.."
repo=$(pwd)

image=node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752
vol=saas-rescue-audit-node-modules
project=out/sample-project
target=docs/sample-report.md

rm -rf "$project"
mkdir -p "$project/app/api/stripe/webhook" "$project/app/api/generate" "$project/app/api/billing/portal" \
  "$project/app/api/generations/[id]" "$project/components" "$project/lib" "$project/supabase/migrations"

cat > "$project/package.json" <<'EOF'
{
  "name": "member-hub",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "@supabase/supabase-js": "^2.45.0",
    "next": "latest",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "stripe": "^17.0.0"
  }
}
EOF

cat > "$project/next.config.mjs" <<'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: { ignoreBuildErrors: true },
};

export default nextConfig;
EOF

cat > "$project/.env.local" <<'EOF'
NEXT_PUBLIC_SUPABASE_URL=https://example-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=replace-with-anon-key
SUPABASE_SERVICE_ROLE_KEY=replace-with-service-role-key
STRIPE_SECRET_KEY=replace-with-stripe-secret-key
STRIPE_WEBHOOK_SECRET=replace-with-webhook-secret
EOF

cat > "$project/supabase/migrations/0001_init.sql" <<'EOF'
-- Created from the Supabase dashboard, then exported.

create table public.members (
  id uuid primary key references auth.users (id) on delete cascade,
  plan text not null default 'free',
  stripe_customer_id text
);

create table public.generations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  prompt text not null,
  result text,
  created_at timestamptz not null default now()
);

create table public.credit_ledger (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  delta integer not null,
  reason text
);

create table public.waitlist (
  id uuid primary key default gen_random_uuid(),
  email text not null
);
EOF

cat > "$project/supabase/migrations/0002_policies.sql" <<'EOF'
alter table public.members enable row level security;
alter table public.generations enable row level security;
alter table public.waitlist enable row level security;

-- the dashboard could not load the plan, so everyone can read every member
create policy "members readable" on public.members
  for select using (true);

create policy "members update own" on public.members
  for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

-- inserts were failing with an RLS error
create policy "generations all" on public.generations
  for all to authenticated
  using (true) with check (true);
EOF

cat > "$project/lib/auth.ts" <<'EOF'
import { cookies } from "next/headers";
import { admin } from "@/lib/admin";

export async function getUser() {
  const token = (await cookies()).get("sb-access-token")?.value;
  if (!token) return null;
  const { data } = await admin.auth.getUser(token);
  return data.user;
}
EOF

cat > "$project/lib/admin.ts" <<'EOF'
import { createClient } from "@supabase/supabase-js";

// one client for everything, so there are no more permission errors
export const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);
EOF

cat > "$project/app/api/stripe/webhook/route.ts" <<'EOF'
import Stripe from "stripe";
import { NextResponse } from "next/server";
import { admin } from "@/lib/admin";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature") ?? "";
  const event = stripe.webhooks.constructEvent(payload, signature, process.env.STRIPE_WEBHOOK_SECRET!);

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      await admin.from("members").update({ plan: "pro" }).eq("stripe_customer_id", session.customer);
      break;
    }
    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      await admin.from("members").update({ plan: "free" }).eq("stripe_customer_id", subscription.customer);
      break;
    }
    default:
      return NextResponse.json({ error: `Unhandled event ${event.type}` }, { status: 500 });
  }

  return NextResponse.json({ received: true });
}
EOF

cat > "$project/app/api/generate/route.ts" <<'EOF'
import { NextResponse } from "next/server";
import { admin } from "@/lib/admin";

export async function POST(request: Request) {
  const { userId, prompt } = await request.json();
  const { data } = await admin
    .from("generations")
    .insert({ user_id: userId, prompt })
    .select()
    .single();
  return NextResponse.json(data);
}
EOF

cat > "$project/app/api/generations/[id]/route.ts" <<'EOF'
import { NextResponse } from "next/server";
import { getUser } from "@/lib/auth";
import { admin } from "@/lib/admin";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { id } = await params;
  const { data } = await admin.from("generations").select("*").eq("id", id).single();
  return NextResponse.json(data);
}
EOF

cat > "$project/app/api/billing/portal/route.ts" <<'EOF'
import Stripe from "stripe";
import { NextResponse } from "next/server";
import { getUser } from "@/lib/auth";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { customerId } = await request.json();
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${process.env.SITE_URL}/account`,
  });
  return NextResponse.json({ url: session.url });
}
EOF

cat > "$project/components/Dashboard.tsx" <<'EOF'
"use client";

export function Dashboard({ html }: { html: string }) {
  const key = process.env.STRIPE_SECRET_KEY;
  return <div data-configured={Boolean(key)} dangerouslySetInnerHTML={{ __html: html }} />;
}
EOF

# build the tool once (the only step with network access); node_modules lives in a docker volume
docker volume create "$vol" >/dev/null
docker run --rm -u 0 -v "$vol:/nm" "$image" chown "$(id -u):$(id -g)" /nm >/dev/null
docker run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  -e HOME=/tmp/home -e npm_config_cache=/tmp/npm-cache -e npm_config_update_notifier=false \
  -v "$repo:/work" -v "$vol:/work/node_modules" -w /work "$image" \
  sh -c 'npm ci --ignore-scripts --silent && npm run build --silent' >&2

# audit the project: no network, read-only mounts, the report is the tool's stdout
tmp=$(mktemp "$repo/out/sample-report.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT TERM
rc=0
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --read-only \
  -v "$repo:/work:ro" -v "$vol:/work/node_modules:ro" -v "$repo/$project:/audit:ro" -w /work "$image" \
  node dist/cli.js /audit --markdown > "$tmp" || rc=$?
if [ "$rc" -ne 1 ]; then
  echo "make-sample-report: saas-audit exited $rc, expected 1 (findings)" >&2
  exit 1
fi

mkdir -p docs
mv "$tmp" "$target"
chmod 644 "$target"
echo "wrote $target ($(wc -l < "$target" | tr -d ' ') lines)"
