create table if not exists public.online_sessions (
  socket_id text primary key,
  username text not null,
  group_name text not null,
  channel_name text not null,
  peer_id text,
  mic_status boolean default false,
  floor_status text default 'idle',
  updated_at timestamptz default now()
);
create index if not exists online_sessions_room_idx on public.online_sessions(group_name, channel_name);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  username text,
  action text,
  target text,
  detail text,
  created_at timestamptz default now()
);
