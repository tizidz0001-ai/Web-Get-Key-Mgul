-- =====================================================================
-- GET KEY SECURITY HARDENING V13 - 2026-08-01
-- Chạy TOÀN BỘ file trong Supabase > SQL Editor, sau đó deploy lại Edge Function.
--
-- Mục tiêu:
-- 1) Claim key atomic, chống race condition / request đồng thời.
-- 2) Một session chỉ dùng một lần; một key chỉ được cấp một lần.
-- 3) Giới hạn create-session / claim / admin-login ở database.
-- 4) Không cho anon/authenticated đọc hoặc gọi trực tiếp kho key/RPC nhạy cảm.
-- 5) Lưu security log không chứa raw token/key.
-- =====================================================================

-- ---------------------------------------------------------------------
-- A. Bổ sung cột cần thiết cho session hiện có.
-- ---------------------------------------------------------------------
alter table public.key_sessions
  add column if not exists creator_ip text;

-- Bảo đảm token không trùng. Nếu bảng đã có unique constraint thì câu này vô hại.
create unique index if not exists key_sessions_token_uidx
  on public.key_sessions(token);

-- Bảo đảm key không trùng nội dung.
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

-- Giữ tương thích với code cũ nếu có nơi vẫn gọi bump_session_limit.
create or replace function public.bump_session_limit(
  p_ip text,
  p_max integer default 20
)
returns table (allowed boolean, current_count integer)
language sql
security definer
set search_path = public
as $$
  select *
  from public.bump_request_limit('create-session', p_ip, p_max, 3600);
$$;

-- ---------------------------------------------------------------------
-- C. Hạn mức key mỗi IP/ngày. KHÔNG lưu raw key trong bảng hạn mức.
-- ---------------------------------------------------------------------
create table if not exists public.claim_limits (
  ip          text        not null,
  vn_date     date        not null,
  claim_count integer     not null default 0,
  last_key    text,
  updated_at  timestamptz not null default now(),
  primary key (ip, vn_date)
);

-- Xóa dữ liệu key cũ khỏi cột last_key nếu bản trước từng lưu.
update public.claim_limits set last_key = null where last_key is not null;

-- ---------------------------------------------------------------------
-- D. Lịch sử claim: unique theo session và unique theo key.
-- Không lưu key_value để giảm rủi ro lộ kho key từ log/audit.
-- ---------------------------------------------------------------------
create table if not exists public.claims (
  id            bigserial primary key,
  session_token uuid        not null unique,
  key_id        uuid        not null unique,
  claim_ip      text,
  claimed_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- E. Security logs. Chỉ backend service_role được ghi/đọc.
-- ---------------------------------------------------------------------
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
-- F. CLAIM ATOMIC - không gọi claim_key cũ nữa.
-- Toàn bộ lock session + lock key + update key + ghi claim + tiêu session
-- nằm trong cùng một transaction của PostgreSQL.
-- ---------------------------------------------------------------------
create or replace function public.claim_key_limited(
  p_token     text,
  p_ip        text default '',
  p_device_id text default ''  -- giữ tham số để tương thích, KHÔNG dùng làm auth
)
returns table (key_value text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token      uuid;
  v_ip         text := coalesce(nullif(btrim(coalesce(p_ip, '')), ''), 'unknown');
  v_date       date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
  v_limit      constant integer := 5;
  v_creator_ip text;
  v_expires_at timestamptz;
  v_key_id     uuid;
  v_key_value  text;
  v_count      integer;
begin
  begin
    v_token := p_token::uuid;
  exception when others then
    raise exception 'INVALID_SESSION';
  end;

  -- 1) Khóa session. Request đồng thời cùng token phải xếp hàng tại đây.
  select creator_ip, expires_at
    into v_creator_ip, v_expires_at
  from public.key_sessions
  where token = v_token
  for update;

  if not found then
    raise exception 'INVALID_SESSION';
  end if;

  if v_expires_at is null or v_expires_at <= now() then
    raise exception 'SESSION_EXPIRED';
  end if;

  -- 2) Ràng session với IP đã tạo. Không tin device_id từ client.
  if v_creator_ip is not null
     and btrim(v_creator_ip) <> ''
     and v_creator_ip <> v_ip then
    raise exception 'TOKEN_IP_MISMATCH';
  end if;

  -- 3) Khóa hàng hạn mức theo IP/ngày để chống request đồng thời né quota.
  insert into public.claim_limits(ip, vn_date)
  values (v_ip, v_date)
  on conflict (ip, vn_date) do nothing;

  select claim_count
    into v_count
  from public.claim_limits
  where ip = v_ip and vn_date = v_date
  for update;

  if v_count >= v_limit then
    raise exception 'LIMIT_REACHED';
  end if;

  -- 4) Chọn đúng 1 key còn trống và khóa row ngay trong transaction.
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

  -- 5) Claim key. Row đang bị lock nên không request khác lấy cùng key được.
  update public.keys
     set status = 'claimed',
         claimed_at = now()
   where id = v_key_id
     and status = 'available';

  if not found then
    raise exception 'CLAIM_CONFLICT';
  end if;

  -- 6) Ghi audit với UNIQUE(session_token) và UNIQUE(key_id).
  insert into public.claims(session_token, key_id, claim_ip)
  values (v_token, v_key_id, v_ip);

  -- 7) Tiêu session: replay cùng token sẽ INVALID_SESSION, không có key mới.
  delete from public.key_sessions where token = v_token;

  update public.claim_limits
     set claim_count = claim_count + 1,
         last_key = null,
         updated_at = now()
   where ip = v_ip and vn_date = v_date;

  return query select v_key_value;
end;
$$;

-- ---------------------------------------------------------------------
-- G. RLS + quyền. Frontend không được đọc/ghi trực tiếp bảng nhạy cảm.
-- Edge Function dùng service_role nên vẫn hoạt động.
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

-- service_role được backend sử dụng.
grant all on table public.keys to service_role;
grant all on table public.key_sessions to service_role;
grant all on table public.claim_limits to service_role;
grant all on table public.request_limits to service_role;
grant all on table public.claims to service_role;
grant all on table public.security_logs to service_role;
grant usage, select on all sequences in schema public to service_role;

-- RPC public phải bị khóa. Chỉ service_role được execute.
revoke all on function public.bump_request_limit(text, text, integer, integer) from public, anon, authenticated;
grant execute on function public.bump_request_limit(text, text, integer, integer) to service_role;

revoke all on function public.bump_session_limit(text, integer) from public, anon, authenticated;
grant execute on function public.bump_session_limit(text, integer) to service_role;

revoke all on function public.claim_key_limited(text, text, text) from public, anon, authenticated;
grant execute on function public.claim_key_limited(text, text, text) to service_role;

-- Khóa các RPC cũ nếu đang tồn tại để user không gọi trực tiếp bỏ qua Edge Function.
do $$
begin
  if to_regprocedure('public.claim_key(uuid)') is not null then
    execute 'revoke all on function public.claim_key(uuid) from public, anon, authenticated';
    execute 'grant execute on function public.claim_key(uuid) to service_role';
  end if;

  if to_regprocedure('public.claim_key(text)') is not null then
    execute 'revoke all on function public.claim_key(text) from public, anon, authenticated';
    execute 'grant execute on function public.claim_key(text) to service_role';
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
-- H. Dọn dữ liệu rate/security cũ (có thể chạy định kỳ bằng pg_cron).
-- ---------------------------------------------------------------------
-- delete from public.request_limits where bucket_start < now() - interval '3 days';
-- delete from public.claim_limits where vn_date < (now() at time zone 'Asia/Ho_Chi_Minh')::date - 14;
-- delete from public.security_logs where created_at < now() - interval '30 days';
