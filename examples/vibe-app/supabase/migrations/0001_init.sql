-- Schema as first created in the dashboard SQL editor.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  stripe_customer_id text,
  plan text not null default 'free'
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  name text not null,
  created_at timestamptz not null default now()
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects (id) on delete cascade,
  user_id uuid not null references auth.users (id),
  body text not null
);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  stripe_invoice_id text unique,
  amount_cents integer not null
);

create table public.feedback (
  id uuid primary key default gen_random_uuid(),
  message text not null,
  created_at timestamptz not null default now()
);
