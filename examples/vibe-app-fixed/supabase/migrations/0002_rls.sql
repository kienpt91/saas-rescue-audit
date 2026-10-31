alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.notes enable row level security;
alter table public.invoices enable row level security;
alter table public.feedback enable row level security;
alter table public.plans enable row level security;
alter table public.stripe_events enable row level security;

create policy "profiles select own" on public.profiles
  for select to authenticated
  using (auth.uid() = id);

create policy "profiles update own" on public.profiles
  for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

create policy "projects select own" on public.projects
  for select to authenticated
  using (auth.uid() = user_id);

create policy "projects insert own" on public.projects
  for insert to authenticated
  with check (auth.uid() = user_id);

create policy "projects update own" on public.projects
  for update to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy "projects delete own" on public.projects
  for delete to authenticated
  using (auth.uid() = user_id);

create policy "notes own" on public.notes
  for all to authenticated
  using (auth.uid() = user_id)
  with check (
    auth.uid() = user_id
    and exists (
      select 1 from public.projects p
      where p.id = project_id and p.user_id = auth.uid()
    )
  );

create policy "invoices select own" on public.invoices
  for select to authenticated
  using (auth.uid() = user_id);

create policy "feedback insert own" on public.feedback
  for insert to authenticated
  with check (auth.uid() = user_id);

-- saas-audit-ignore-next-line supabase-policy-permissive -- plans is a public price list, not user data
create policy "plans are public" on public.plans
  for select to anon, authenticated
  using (true);
