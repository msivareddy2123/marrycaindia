-- MarryCAIndia database. Run once in Supabase > SQL Editor.

-- ========== TABLES ==========
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  created_by text not null default 'self' check (created_by in ('self','parent')),
  name text not null check (char_length(name) between 1 and 80),
  gender text not null check (gender in ('man','woman')),
  age int not null check (age between 18 and 80),
  height_in int check (height_in between 48 and 84),
  city text check (char_length(city) <= 60),
  state text check (char_length(state) <= 60),
  profession text check (char_length(profession) <= 40),
  stage text check (char_length(stage) <= 30),
  work text check (char_length(work) <= 120),
  income text check (char_length(income) <= 40),
  community text check (char_length(community) <= 60),
  language text check (char_length(language) <= 40),
  religion text check (char_length(religion) <= 40),
  diet text check (char_length(diet) <= 30),
  interests text[] not null default '{}',
  bio text not null default '' check (char_length(bio) <= 800),
  pmin int,
  pmax int,
  photo_path text,
  verified boolean not null default false,
  paused boolean not null default false,
  trial_ends timestamptz not null default (now() + interval '30 days'),
  paid_until timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.contacts (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  whatsapp text check (char_length(whatsapp) <= 30),
  email text check (char_length(email) <= 120)
);

create table if not exists public.interests (
  id bigint generated always as identity primary key,
  from_id uuid not null references public.profiles(id) on delete cascade,
  to_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted','declined')),
  created_at timestamptz not null default now(),
  check (from_id <> to_id),
  unique (from_id, to_id)
);

create table if not exists public.messages (
  id bigint generated always as identity primary key,
  from_id uuid not null references public.profiles(id) on delete cascade,
  to_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index if not exists messages_pair on public.messages (from_id, to_id, created_at);

create table if not exists public.shortlist (
  user_id uuid not null references public.profiles(id) on delete cascade,
  profile_id uuid not null references public.profiles(id) on delete cascade,
  note text not null default '' check (char_length(note) <= 500),
  created_at timestamptz not null default now(),
  primary key (user_id, profile_id)
);

create table if not exists public.blocks (
  blocker uuid not null references public.profiles(id) on delete cascade,
  blocked uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker, blocked)
);

create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter uuid not null references public.profiles(id) on delete cascade,
  reported uuid not null references public.profiles(id) on delete cascade,
  reason text not null check (char_length(reason) between 1 and 500),
  created_at timestamptz not null default now()
);

-- ========== HELPER FUNCTIONS ==========
create or replace function public.my_gender() returns text
language sql stable security definer set search_path = public as
$$ select gender from public.profiles where id = auth.uid() $$;

create or replace function public.has_access(uid uuid) returns boolean
language sql stable security definer set search_path = public as
$$ select coalesce((select trial_ends > now() or coalesce(paid_until, 'epoch') > now()
                    from public.profiles where id = uid), false) $$;

create or replace function public.is_connected(a uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.interests
                  where status = 'accepted'
                    and ((from_id = a and to_id = b) or (from_id = b and to_id = a))) $$;

create or replace function public.blocked_either(a uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.blocks
                  where (blocker = a and blocked = b) or (blocker = b and blocked = a)) $$;

-- ========== AUTO-CREATE PROFILE AFTER SIGN-UP ==========
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as
$$
declare m jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  insert into public.profiles (id, created_by, name, gender, age, city, state, profession, stage, bio)
  values (
    new.id,
    case when m->>'created_by' = 'parent' then 'parent' else 'self' end,
    left(coalesce(nullif(m->>'name', ''), 'New member'), 80),
    case when m->>'gender' = 'woman' then 'woman' else 'man' end,
    least(80, greatest(18, coalesce(nullif(m->>'age', '')::int, 28))),
    left(m->>'city', 60), left(m->>'state', 60),
    left(m->>'profession', 40), left(m->>'stage', 30),
    left(coalesce(m->>'bio', ''), 800)
  );
  insert into public.contacts (user_id, whatsapp, email)
  values (new.id, left(m->>'whatsapp', 30), left(new.email, 120));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ========== ROW LEVEL SECURITY ==========
alter table public.profiles  enable row level security;
alter table public.contacts  enable row level security;
alter table public.interests enable row level security;
alter table public.messages  enable row level security;
alter table public.shortlist enable row level security;
alter table public.blocks    enable row level security;
alter table public.reports   enable row level security;

-- Column-level rights: members can never set verified / paid_until / trial_ends themselves.
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (name, age, height_in, city, state, profession, stage, work, income, community,
              language, religion, diet, interests, bio, pmin, pmax, photo_path, paused)
  on public.profiles to authenticated;

revoke all on public.contacts from anon, authenticated;
grant select on public.contacts to authenticated;
grant update (whatsapp) on public.contacts to authenticated;

revoke all on public.interests from anon, authenticated;
grant select on public.interests to authenticated;
grant insert (from_id, to_id) on public.interests to authenticated;
grant update (status) on public.interests to authenticated;

revoke all on public.messages from anon, authenticated;
grant select on public.messages to authenticated;
grant insert (from_id, to_id, body) on public.messages to authenticated;

revoke all on public.shortlist from anon, authenticated;
grant select, insert, update, delete on public.shortlist to authenticated;

revoke all on public.blocks from anon, authenticated;
grant select, insert, delete on public.blocks to authenticated;

revoke all on public.reports from anon, authenticated;
grant insert (reporter, reported, reason) on public.reports to authenticated;

-- profiles: see your own, plus active opposite-gender members who have not blocked you
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated using (
  id = auth.uid()
  or (not paused and gender <> public.my_gender() and not public.blocked_either(id, auth.uid()))
);
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- contacts: yours, or after both sides accepted
drop policy if exists contacts_select on public.contacts;
create policy contacts_select on public.contacts for select to authenticated using (
  user_id = auth.uid() or public.is_connected(auth.uid(), user_id)
);
drop policy if exists contacts_update on public.contacts;
create policy contacts_update on public.contacts for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- interests
drop policy if exists interests_select on public.interests;
create policy interests_select on public.interests for select to authenticated using (
  from_id = auth.uid() or to_id = auth.uid()
);
drop policy if exists interests_insert on public.interests;
create policy interests_insert on public.interests for insert to authenticated with check (
  from_id = auth.uid() and public.has_access(auth.uid())
  and not public.blocked_either(from_id, to_id)
  and exists (select 1 from public.profiles p where p.id = to_id and not p.paused)
);
drop policy if exists interests_update on public.interests;
create policy interests_update on public.interests for update to authenticated
  using (to_id = auth.uid()) with check (to_id = auth.uid() and status in ('accepted','declined'));

-- messages: only between connected members
drop policy if exists messages_select on public.messages;
create policy messages_select on public.messages for select to authenticated using (
  from_id = auth.uid() or to_id = auth.uid()
);
drop policy if exists messages_insert on public.messages;
create policy messages_insert on public.messages for insert to authenticated with check (
  from_id = auth.uid() and public.has_access(auth.uid())
  and public.is_connected(from_id, to_id) and not public.blocked_either(from_id, to_id)
);

-- shortlist, blocks, reports: yours only
drop policy if exists shortlist_all on public.shortlist;
create policy shortlist_all on public.shortlist for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists blocks_select on public.blocks;
create policy blocks_select on public.blocks for select to authenticated using (blocker = auth.uid());
drop policy if exists blocks_insert on public.blocks;
create policy blocks_insert on public.blocks for insert to authenticated with check (blocker = auth.uid());
drop policy if exists blocks_delete on public.blocks;
create policy blocks_delete on public.blocks for delete to authenticated using (blocker = auth.uid());
drop policy if exists reports_insert on public.reports;
create policy reports_insert on public.reports for insert to authenticated with check (reporter = auth.uid());

-- ========== PHOTO STORAGE ==========
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 3145728, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists photos_select on storage.objects;
create policy photos_select on storage.objects for select to authenticated using (
  bucket_id = 'photos' and (
    (storage.foldername(name))[1] = auth.uid()::text
    or public.is_connected(auth.uid(), ((storage.foldername(name))[1])::uuid)
  )
);
drop policy if exists photos_insert on storage.objects;
create policy photos_insert on storage.objects for insert to authenticated with check (
  bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
);
drop policy if exists photos_update on storage.objects;
create policy photos_update on storage.objects for update to authenticated using (
  bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
);
drop policy if exists photos_delete on storage.objects;
create policy photos_delete on storage.objects for delete to authenticated using (
  bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
);

-- live chat updates
alter publication supabase_realtime add table public.messages;
