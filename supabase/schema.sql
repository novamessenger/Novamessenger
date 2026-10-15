-- NOVA starter schema for Supabase
-- Run this in Supabase Dashboard > SQL Editor.
-- SECURITY NOTE:
-- This schema uses Supabase anonymous auth sessions. A code such as 001 is NOT a secret.
-- Anyone can try to claim an unused code. Existing claimed codes cannot be silently taken over,
-- but this starter does not provide secure recovery on a second device. Add a private PIN/password
-- and server-side verification before using with real private conversations.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  code text not null unique check (code ~ '^0(0[1-9]|[12][0-9]|3[0-3])$'),
  display_name text not null check (char_length(display_name) between 2 and 30),
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now(),
  constraint no_self_message check (sender_id <> receiver_id)
);

create index if not exists messages_pair_time_idx
  on public.messages (sender_id, receiver_id, created_at desc);
create index if not exists messages_receiver_time_idx
  on public.messages (receiver_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.messages enable row level security;

-- Signed-in users may see the directory and update only their own display name.
drop policy if exists "profiles directory for authenticated users" on public.profiles;
create policy "profiles directory for authenticated users"
on public.profiles for select to authenticated using (true);

drop policy if exists "users insert own profile" on public.profiles;
create policy "users insert own profile"
on public.profiles for insert to authenticated
with check (auth.uid() = id);

drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile"
on public.profiles for update to authenticated
using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "participants read messages" on public.messages;
create policy "participants read messages"
on public.messages for select to authenticated
using (auth.uid() = sender_id or auth.uid() = receiver_id);

drop policy if exists "sender inserts own messages" on public.messages;
create policy "sender inserts own messages"
on public.messages for insert to authenticated
with check (
  auth.uid() = sender_id
  and exists (select 1 from public.profiles p where p.id = sender_id)
  and exists (select 1 from public.profiles p where p.id = receiver_id)
);

-- Enable Realtime for live incoming messages.
do $$
begin
  alter publication supabase_realtime add table public.messages;
exception when duplicate_object then null;
when undefined_object then null;
end $$;

-- The UI displays only registered profiles. The 33 codes are accepted by the frontend,
-- but profiles appear only after their first successful registration.
