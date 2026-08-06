-- =====================================================================
-- GET KEY V16 - KHÔNG CHECK IP / DEVICE ID + KHÔNG GIỚI HẠN THỜI GIAN - 2026-08-06
-- Chạy TOÀN BỘ file trong Supabase > SQL Editor, sau đó deploy index.ts V16.1.
--
-- V14 bổ sung:
-- 1) Session có vòng đời creating -> shortened -> claimed.
-- 2) Chỉ session đã tạo link rút gọn thành công mới được claim.
-- 3) URL đích dùng landing code ngẫu nhiên, không lộ token session UUID.
-- 4) Không kiểm tra IP, Device ID, journey secret hoặc User-Agent.
-- 5) Không chặn theo thời gian; link đích nhanh vẫn được claim.
-- 6) Claim atomic, một session/một key chỉ dùng đúng một lần.
-- 7) Khóa RPC cũ để Edge Function cũ không thể bỏ qua vòng đời V14.
-- =====================================================================

-- ---------------------------------------------------------------------
-- A. Nâng cấp bảng session.
-- ---------------------------------------------------------------------
alter table public.key_sessions
  add column if not exists created_at timestamptz not null default now(),
  add column if not exists landing_code_hash text,
  add column if not exists status text not null default 'creating',
  add column if not exists link_ready_at timestamptz,
  add column if not exists claim_not_before timestamptz,
  add column if not exists shortener_layers integer;

alter table public.key_sessions
  alter column created_at set default now();

-- Xóa session cũ để tránh link phiên bản trước gọi nhầm RPC mới.
delete from public.key_sessions;

create unique index if not exists key_sessions_token_uidx
  on public.key_sessions(token);

create unique index if not exists key_sessions_landing_code_hash_uidx
  on public.key_sessions(landing_code_hash)
  where landing_code_hash is not null;

create index if not exists key_sessions_expires_at_idx
  on public.key_sessions(expires_at);

create unique index if not exists keys_key_value_uidx
  on public.keys(key_value);

-- ---------------------------------------------------------------------
-- B. Rate limit generic: scope + subject + time bucket.
-- ---------------------------------------------------------------------
create table if not exists public.request_limits (
  scope          text        not null,
  subject        text        not null,
  bucket_start   timestamptz not null,
  request_count  integer     not null default 0,
  updated_at     timestamptz not null default now(),
  primary key (scope, subject, bucket_start)
);

create or replace function public.bump_request_limit(
  p_scope          text,
  p_subject        text,
  p_max            integer,
  p_window_seconds integer
)
returns table (allowed boolean, current_count integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scope   text := left(coalesce(nullif(btrim(p_scope), ''), 'unknown'), 80);
  v_subject text := left(coalesce(nullif(btrim(p_subject), ''), 'unknown'), 256);
  v_max     integer := greatest(1, least(coalesce(p_max, 1), 100000));
  v_window  integer := greatest(60, least(coalesce(p_window_seconds, 60), 86400));
  v_bucket  timestamptz;
  v_count   integer;
begin
  v_bucket := to_timestamp(
    floor(extract(epoch from clock_timestamp()) / v_window) * v_window
  );

  insert into public.request_limits(scope, subject, bucket_start)
  values (v_scope, v_subject, v_bucket)
  on conflict (scope, subject, bucket_start) do nothing;

  select request_count
    into v_count
  from public.request_limits
  where scope = v_scope
    and subject = v_subject
    and bucket_start = v_bucket
  for update;

  if v_count >= v_max then
    return query select false, v_count;
    return;
  end if;

  update public.request_limits
     set request_count = request_count + 1,
         updated_at = now()
   where scope = v_scope
     and subject = v_subject
     and bucket_start = v_bucket
  returning request_count into v_count;

  return query select true, v_count;
end;
$$;

-- Xóa RPC giới hạn theo IP của phiên bản cũ nếu đang tồn tại.
drop function if exists public.bump_session_limit(text, integer);

-- ---------------------------------------------------------------------
-- C. Bảng hạn mức cũ được giữ để tương thích, nhưng V16 không còn sử dụng.
-- ---------------------------------------------------------------------
create table if not exists public.claim_limits (
  ip          text        not null,
  vn_date     date        not null,
  claim_count integer     not null default 0,
  last_key    text,
  updated_at  timestamptz not null default now(),
  primary key (ip, vn_date)
);

update public.claim_limits set last_key = null where last_key is not null;

-- ---------------------------------------------------------------------
-- D. Lịch sử claim và security logs.
-- ---------------------------------------------------------------------
create table if not exists public.claims (
  id            bigserial primary key,
  session_token uuid        not null unique,
  key_id        uuid        not null unique,
  claim_ip      text,
  claimed_at    timestamptz not null default now()
);

create table if not exists public.security_logs (
  id          bigserial primary key,
  event_type  text        not null,
  ip          text,
  token_hash  text,
  user_agent  text,
  details     jsonb       not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

create index if not exists security_logs_created_at_idx
  on public.security_logs(created_at desc);
create index if not exists security_logs_event_type_idx
  on public.security_logs(event_type, created_at desc);

-- ---------------------------------------------------------------------
-- E. Chuyển session sang trạng thái shortened CHỈ SAU KHI API rút gọn thành công.
-- ---------------------------------------------------------------------
drop function if exists public.mark_session_shortened_v14(text, integer, integer);
drop function if exists public.mark_session_shortened_v14(text, integer);

create or replace function public.mark_session_shortened_v14(
  p_token text,
  p_layers integer
)
returns table (ready boolean, link_ready_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token uuid;
  v_ready_at timestamptz;
begin
  begin
    v_token := p_token::uuid;
  exception when others then
    raise exception 'INVALID_SESSION';
  end;

  update public.key_sessions
     set status = 'shortened',
         link_ready_at = now(),
         claim_not_before = now(),
         shortener_layers = greatest(1, least(coalesce(p_layers, 1), 6))
   where token = v_token
     and status = 'creating'
     and expires_at > now()
     and landing_code_hash is not null
  returning key_sessions.link_ready_at into v_ready_at;

  if not found then
    raise exception 'SESSION_NOT_READY';
  end if;

  return query select true, v_ready_at;
end;
$$;

-- ---------------------------------------------------------------------
-- F. CLAIM ATOMIC V14.
-- Tìm session bằng HASH của landing code, kiểm tra trạng thái session,
-- khóa session + key rồi claim và tiêu session trong cùng transaction.
-- ---------------------------------------------------------------------
drop function if exists public.claim_key_limited_v14(text, text, text, text, text);
drop function if exists public.claim_key_limited_v14(text, text, text);
drop function if exists public.claim_key_limited_v14(text);

create or replace function public.claim_key_limited_v14(
  p_landing_hash text
)
returns table (key_value text)
language plpgsql
security definer
set search_path = public
as $$
declare
  -- V16 chỉ xác minh landing code và trạng thái session.
  v_landing_hash     text := lower(btrim(coalesce(p_landing_hash, '')));
  v_token            uuid;
  v_expires_at       timestamptz;
  v_link_ready_at    timestamptz;
  v_status           text;
  v_key_id           uuid;
  v_key_value        text;
begin
  if v_landing_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_LANDING_CODE';
  end if;

  select token, expires_at, link_ready_at, status
    into v_token, v_expires_at, v_link_ready_at, v_status
  from public.key_sessions
  where landing_code_hash = v_landing_hash
  for update;

  if not found then
    raise exception 'INVALID_SESSION';
  end if;

  if v_expires_at is null or v_expires_at <= now() then
    raise exception 'SESSION_EXPIRED';
  end if;

  if v_status <> 'shortened' or v_link_ready_at is null then
    raise exception 'LINK_NOT_READY';
  end if;


  select id, key_value
    into v_key_id, v_key_value
  from public.keys
  where status = 'available'
  order by created_at asc, id asc
  for update skip locked
  limit 1;

  if not found or v_key_value is null or btrim(v_key_value) = '' then
    raise exception 'OUT_OF_KEYS';
  end if;

  update public.keys
     set status = 'claimed',
         claimed_at = now()
   where id = v_key_id
     and status = 'available';

  if not found then
    raise exception 'CLAIM_CONFLICT';
  end if;

  insert into public.claims(session_token, key_id, claim_ip)
  values (v_token, v_key_id, null);

  delete from public.key_sessions where token = v_token;

  return query select v_key_value;
end;
$$;

-- Xóa RPC cũ có tham số IP/Device ID để tránh gọi nhầm phiên bản.
drop function if exists public.claim_key_limited(text, text, text);

-- ---------------------------------------------------------------------
-- G. RLS + quyền.
-- ---------------------------------------------------------------------
alter table public.keys enable row level security;
alter table public.key_sessions enable row level security;
alter table public.claim_limits enable row level security;
alter table public.request_limits enable row level security;
alter table public.claims enable row level security;
alter table public.security_logs enable row level security;

revoke all on table public.keys from anon, authenticated;
revoke all on table public.key_sessions from anon, authenticated;
revoke all on table public.claim_limits from anon, authenticated;
revoke all on table public.request_limits from anon, authenticated;
revoke all on table public.claims from anon, authenticated;
revoke all on table public.security_logs from anon, authenticated;

grant all on table public.keys to service_role;
grant all on table public.key_sessions to service_role;
grant all on table public.claim_limits to service_role;
grant all on table public.request_limits to service_role;
grant all on table public.claims to service_role;
grant all on table public.security_logs to service_role;
grant usage, select on all sequences in schema public to service_role;

revoke all on function public.bump_request_limit(text, text, integer, integer) from public, anon, authenticated;
grant execute on function public.bump_request_limit(text, text, integer, integer) to service_role;

revoke all on function public.mark_session_shortened_v14(text, integer) from public, anon, authenticated;
grant execute on function public.mark_session_shortened_v14(text, integer) to service_role;

revoke all on function public.claim_key_limited_v14(text) from public, anon, authenticated;
grant execute on function public.claim_key_limited_v14(text) to service_role;

-- Khóa các RPC cũ nếu đang tồn tại.
do $$
begin
  if to_regprocedure('public.claim_key(uuid)') is not null then
    execute 'revoke all on function public.claim_key(uuid) from public, anon, authenticated';
  end if;

  if to_regprocedure('public.claim_key(text)') is not null then
    execute 'revoke all on function public.claim_key(text) from public, anon, authenticated';
  end if;

  if to_regprocedure('public.admin_delete_keys(uuid[])') is not null then
    execute 'revoke all on function public.admin_delete_keys(uuid[]) from public, anon, authenticated';
    execute 'grant execute on function public.admin_delete_keys(uuid[]) to service_role';
  end if;

  if to_regprocedure('public.admin_set_key_status(uuid[],text)') is not null then
    execute 'revoke all on function public.admin_set_key_status(uuid[],text) from public, anon, authenticated';
    execute 'grant execute on function public.admin_set_key_status(uuid[],text) to service_role';
  end if;
end $$;

-- ---------------------------------------------------------------------
-- H. Dọn dữ liệu cũ (có thể chạy định kỳ).
-- ---------------------------------------------------------------------
-- delete from public.key_sessions where expires_at < now();
-- delete from public.request_limits where bucket_start < now() - interval '3 days';
-- delete from public.claim_limits where vn_date < (now() at time zone 'Asia/Ho_Chi_Minh')::date - 14;
-- delete from public.security_logs where created_at < now() - interval '30 days';
