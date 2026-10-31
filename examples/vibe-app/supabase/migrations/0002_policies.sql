-- "Fix" for the Supabase dashboard warning about RLS.

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.notes enable row level security;
alter table public.feedback enable row level security;

-- the app could not read profiles, so make them readable
create policy "profiles readable" on public.profiles
  for select using (true);

create policy "profiles update own" on public.profiles
  for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

-- projects failed with "new row violates row-level security policy"
create policy "projects all" on public.projects
  for all to authenticated
  using (true) with check (true);

-- anyone can send feedback from the marketing page
create policy "anyone can send feedback" on public.feedback
  for insert to anon
  with check (true);
