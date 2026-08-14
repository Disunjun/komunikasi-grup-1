-- Skema yang SAMA dengan yang dibuat otomatis oleh server.js (initializeDatabase).
-- Jalankan ini hanya jika ingin menyiapkan database secara manual terlebih dahulu.
-- Kolom audit_logs memakai admin_name (sesuai kode server), bukan username.

create table if not exists public.users (
  id bigserial primary key,
  username varchar(100) unique not null,
  password_hash text,
  role varchar(30) default 'user',
  active boolean default true,
  banned boolean default false,
  muted boolean default false,
  created_by varchar(100) default 'system',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists public.online_sessions (
  socket_id varchar(255) primary key,
  username varchar(100) not null,
  group_name varchar(100),
  channel_name varchar(100),
  peer_id varchar(255),
  mic_status boolean default false,
  floor_status varchar(30) default 'idle',
  updated_at timestamptz default now()
);
create index if not exists online_sessions_room_idx on public.online_sessions(group_name, channel_name);

create table if not exists public.chat_messages (
  id bigserial primary key,
  username varchar(100) not null,
  group_name varchar(100),
  channel_name varchar(100),
  message text not null,
  created_at timestamptz default now()
);

create table if not exists public.app_config (
  config_key varchar(100) primary key,
  config_value jsonb not null,
  updated_by varchar(100) default 'system',
  updated_at timestamptz default now()
);

create table if not exists public.audit_logs (
  id bigserial primary key,
  admin_name varchar(100) not null,
  action varchar(100) not null,
  target text,
  detail text,
  created_at timestamptz default now()
);

create table if not exists public.activity_logs (
  id bigserial primary key,
  username varchar(100) not null,
  group_name varchar(100),
  channel_name varchar(100),
  action varchar(30) not null,
  created_at timestamptz default now()
);
create index if not exists idx_activity_logs_created_at on public.activity_logs(created_at desc);
create index if not exists idx_activity_logs_group_channel on public.activity_logs(group_name, channel_name);
