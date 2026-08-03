-- =====================================================================
-- GET KEY SECURITY HARDENING V14 + BẮT BUỘC 30 GIÂY - 2026-08-04
-- Chạy TOÀN BỘ file trong Supabase > SQL Editor, sau đó deploy index.ts V14.
--
-- V14 bổ sung:
-- 1) Session có vòng đời creating -> shortened -> claimed.
-- 2) Chỉ session đã tạo link rút gọn thành công mới được claim.
-- 3) URL đích dùng landing code ngẫu nhiên, không lộ token session UUID.
-- 4) Ràng buộc cùng IP + cùng trình duyệt bằng device hash, journey secret hash,
--    user-agent hash; tất cả hash được tạo ở Edge Function.
-- 5) Bắt buộc đủ ít nhất 30 giây từ lúc server nhận yêu cầu tạo link mới cấp key.
-- 6) Claim atomic, một session/một key chỉ dùng đúng một lần.
-- 7) Khóa RPC cũ để Edge Function cũ không thể bỏ qua vòng đời V14.
-- =====================================================================

-- ---------------------------------------------------------------------
-- A. Nâng cấp bảng session.
-- ---------------------------------------------------------------------
alter table public.key_sessions
  add column if not exists created_at timestamptz not null default now(),
  add column if not exists creator_ip text,
  add column if not exists creator_device_hash text,
  add column if not exists journey_secret_hash text,
  add column if not exists creator_ua_hash text,
  add column if not exists landing_code_hash text,
  add column if not exists status text not null default 'creating',
  add column if not exists link_ready_at timestamptz,
  add column if not exists claim_not_before timestamptz,
  add column if not exists shortener_layers integer;

alter table public.key_sessions
  alter column created_at set default now();

-- Link cũ V13 không có landing code/journey binding nên cố ý vô hiệu hóa.
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
-- C. Hạn mức key mỗi IP/ngày.
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
create or replace function public.mark_session_shortened_v14(
  p_token text,
  p_layers integer,
  p_min_seconds integer
)
returns table (ready boolean, claim_not_before timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token uuid;
  v_wait integer := greatest(30, least(coalesce(p_min_seconds, 30), 1800));
  v_not_before timestamptz;
begin
  begin
    v_token := p_token::uuid;
  exception when others then
    raise exception 'INVALID_SESSION';
  end;

  update public.key_sessions
     set status = 'shortened',
         link_ready_at = now(),
         -- Tính từ created_at (lúc backend nhận create-session), KHÔNG tính
         -- lại từ lúc API rút gọn hoàn tất. Vì vậy thời gian tạo link cũng
         -- được cộng vào tổng thời gian 30 giây.
         claim_not_before = created_at + make_interval(secs => v_wait),
         shortener_layers = greatest(1, least(coalesce(p_layers, 1), 6))
   where token = v_token
     and status = 'creating'
     and expires_at > now()
     and landing_code_hash is not null
     and journey_secret_hash is not null
     and creator_device_hash is not null
     and creator_ua_hash is not null
  returning key_sessions.claim_not_before into v_not_before;

  if not found then
    raise exception 'SESSION_NOT_READY';
  end if;

  return query select true, v_not_before;
end;
$$;

-- ---------------------------------------------------------------------
-- F. CLAIM ATOMIC V14.
-- Tìm session bằng HASH của landing code, kiểm tra trạng thái/binding/thời gian,
-- khóa session + key rồi claim và tiêu session trong cùng transaction.
-- ---------------------------------------------------------------------
create or replace function public.claim_key_limited_v14(
  p_landing_hash text,
  p_ip text default '',
  p_device_hash text default '',
  p_journey_hash text default '',
  p_ua_hash text default ''
)
returns table (key_value text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_ip                  text := coalesce(nullif(btrim(coalesce(p_ip, '')), ''), 'unknown');
  v_landing_hash        text := lower(btrim(coalesce(p_landing_hash, '')));
  v_device_hash         text := lower(btrim(coalesce(p_device_hash, '')));
  v_journey_hash        text := lower(btrim(coalesce(p_journey_hash, '')));
  v_ua_hash             text := lower(btrim(coalesce(p_ua_hash, '')));
  v_date                date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
  v_limit               constant integer := 5;
  v_token               uuid;
  v_creator_ip          text;
  v_creator_device_hash text;
  v_journey_secret_hash text;
  v_creator_ua_hash     text;
  v_expires_at          timestamptz;
  v_link_ready_at       timestamptz;
  v_claim_not_before    timestamptz;
  v_status              text;
  v_key_id              uuid;
  v_key_value           text;
  v_count               integer;
begin
  if v_landing_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_LANDING_CODE';
  end if;

  -- 1) Khóa đúng session theo landing hash.
  select token,
         creator_ip,
         creator_device_hash,
         journey_secret_hash,
         creator_ua_hash,
         expires_at,
         link_ready_at,
         claim_not_before,
         status
    into v_token,
         v_creator_ip,
         v_creator_device_hash,
         v_journey_secret_hash,
         v_creator_ua_hash,
         v_expires_at,
         v_link_ready_at,
         v_claim_not_before,
         v_status
  from public.key_sessions
  where landing_code_hash = v_landing_hash
  for update;

  if not found then
    raise exception 'INVALID_SESSION';
  end if;

  if v_expires_at is null or v_expires_at <= now() then
    raise exception 'SESSION_EXPIRED';
  end if;

  -- 2) Session chỉ claim được sau khi backend đã tạo link rút gọn thành công.
  if v_status <> 'shortened' or v_link_ready_at is null then
    raise exception 'LINK_NOT_READY';
  end if;

  if v_claim_not_before is null or now() < v_claim_not_before then
    raise exception 'JOURNEY_TOO_FAST';
  end if;

  -- 3) Ràng buộc cùng mạng và cùng trình duyệt đã tạo link.
  if v_creator_ip is null or btrim(v_creator_ip) = '' or v_creator_ip <> v_ip then
    raise exception 'TOKEN_IP_MISMATCH';
  end if;

  if v_creator_device_hash is null or v_creator_device_hash <> v_device_hash then
    raise exception 'DEVICE_MISMATCH';
  end if;

  if v_journey_secret_hash is null or v_journey_secret_hash <> v_journey_hash then
    raise exception 'JOURNEY_MISMATCH';
  end if;

  if v_creator_ua_hash is null or v_creator_ua_hash <> v_ua_hash then
    raise exception 'USER_AGENT_MISMATCH';
  end if;

  -- 4) Hạn mức theo IP/ngày, khóa row để chống request đồng thời.
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

  -- 5) Lấy đúng một key còn trống và khóa row.
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
  values (v_token, v_key_id, v_ip);

  update public.claim_limits
     set claim_count = claim_count + 1,
         last_key = null,
         updated_at = now()
   where ip = v_ip and vn_date = v_date;

  -- 6) Tiêu session. Replay landing code không thể lấy key mới.
  delete from public.key_sessions where token = v_token;

  return query select v_key_value;
end;
$$;

-- RPC V13 bị vô hiệu hóa có chủ đích. Nếu Edge Function cũ còn chạy, nó sẽ
-- báo API_VERSION_OUTDATED thay vì cấp key theo luồng cũ.
create or replace function public.claim_key_limited(
  p_token text,
  p_ip text default '',
  p_device_id text default ''
)
returns table (key_value text)
language plpgsql
security definer
set search_path = public
as $$
begin
  raise exception 'API_VERSION_OUTDATED';
end;
$$;

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

revoke all on function public.bump_session_limit(text, integer) from public, anon, authenticated;
grant execute on function public.bump_session_limit(text, integer) to service_role;

revoke all on function public.mark_session_shortened_v14(text, integer, integer) from public, anon, authenticated;
grant execute on function public.mark_session_shortened_v14(text, integer, integer) to service_role;

revoke all on function public.claim_key_limited_v14(text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.claim_key_limited_v14(text, text, text, text, text) to service_role;

revoke all on function public.claim_key_limited(text, text, text) from public, anon, authenticated;
grant execute on function public.claim_key_limited(text, text, text) to service_role;

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
