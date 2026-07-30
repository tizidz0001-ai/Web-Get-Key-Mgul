// BẢN ADMIN CÓ XÁC THỰC MẬT KHẨU (SERVER-SIDE)
// Test bằng {"action":"version"} phải trả KEY_API_ADMIN_SECURED_V12_20260728
// KEY_API_VERSION: KEY_API_ADMIN_SECURED_V12_20260728
//
// V11: admin cấu hình nhiều web rút gọn + số lớp (1-6), luân phiên, bỏ qua lớp lỗi.
// V12: chống lạm dụng — Turnstile ở create-session, ràng token với IP tạo nó,
//      rate-limit session/IP/giờ, trần 5 key/IP/ngày (RPC claim_key_limited).
//
// BẮT BUỘC đặt biến môi trường (Supabase > Edge Functions > key-api > Secrets):
//   ADMIN_PASSWORD      = mật khẩu admin (tối thiểu 8 ký tự)
//   ADMIN_TOKEN_SECRET  = chuỗi bí mật ngẫu nhiên dài để ký token (tùy chọn,
//                         nếu bỏ trống sẽ tự suy ra từ ADMIN_PASSWORD + service key)

const KEY_API_VERSION = "KEY_API_ADMIN_SECURED_V12_20260728";

// Token admin sống trong bao lâu (mili giây). Mặc định 12 giờ.
const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function readSupabaseServerKey(): string {
  const legacyKey = String(
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "",
  ).trim();

  if (legacyKey) {
    return legacyKey;
  }

  const secretKeysJson = String(
    Deno.env.get("SUPABASE_SECRET_KEYS") || "",
  ).trim();

  if (!secretKeysJson) {
    return "";
  }

  try {
    const secretKeys = JSON.parse(
      secretKeysJson,
    ) as Record<string, unknown>;

    const defaultKey = String(
      secretKeys.default || "",
    ).trim();

    if (defaultKey) {
      return defaultKey;
    }

    for (const value of Object.values(secretKeys)) {
      const key = String(value || "").trim();

      if (key) {
        return key;
      }
    }
  } catch (error) {
    console.error(
      "SUPABASE_SECRET_KEYS_PARSE_ERROR",
      error,
    );
  }

  return "";
}

function getServerConfig() {
  const supabaseUrl = String(
    Deno.env.get("SUPABASE_URL") || "",
  )
    .trim()
    .replace(/\/+$/, "");

  const serviceRoleKey =
    readSupabaseServerKey();

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SERVER_CONFIG_ERROR", {
      hasSupabaseUrl: Boolean(supabaseUrl),
      hasServerKey: Boolean(serviceRoleKey),
    });

    throw new Error("SERVER_CONFIG_ERROR");
  }

  return {
    supabaseUrl,
    serviceRoleKey,
  };
}

// ---------------------------------------------------------------------------
// XÁC THỰC ADMIN (server-side, không thể bị vượt qua bằng cách ẩn admin.html)
// ---------------------------------------------------------------------------

function readAdminPassword(): string {
  return String(
    Deno.env.get("ADMIN_PASSWORD") || "",
  ).trim();
}

function getTokenSecret(): string {
  const explicit = String(
    Deno.env.get("ADMIN_TOKEN_SECRET") || "",
  ).trim();

  if (explicit) {
    return explicit;
  }

  // Suy ra bí mật ổn định từ mật khẩu + service key nếu không đặt riêng.
  const password = readAdminPassword();
  const { serviceRoleKey } = getServerConfig();

  return `${password}::${serviceRoleKey}`;
}

const textEncoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64UrlEncode(input: string): string {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(input: string): string {
  const padded = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(
      input.length + ((4 - (input.length % 4)) % 4),
      "=",
    );

  return atob(padded);
}

async function hmacSha256Hex(
  secret: string,
  message: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    textEncoder.encode(message),
  );

  return bytesToHex(new Uint8Array(signature));
}

// So sánh chuỗi theo thời gian hằng số để chống timing attack.
function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = textEncoder.encode(a);
  const bBytes = textEncoder.encode(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let mismatch = 0;

  for (let i = 0; i < aBytes.length; i++) {
    mismatch |= aBytes[i] ^ bBytes[i];
  }

  return mismatch === 0;
}

// Token dạng: base64url(payloadJson) + "." + hmacHex
async function issueAdminToken(): Promise<string> {
  const payload = JSON.stringify({
    role: "admin",
    iat: Date.now(),
    exp: Date.now() + ADMIN_TOKEN_TTL_MS,
    nonce: crypto.randomUUID(),
  });

  const encodedPayload = base64UrlEncode(payload);

  const signature = await hmacSha256Hex(
    getTokenSecret(),
    encodedPayload,
  );

  return `${encodedPayload}.${signature}`;
}

async function verifyAdminToken(
  token: unknown,
): Promise<boolean> {
  const raw = String(token || "").trim();

  if (!raw || raw.length > 4096) {
    return false;
  }

  const dotIndex = raw.indexOf(".");

  if (dotIndex <= 0) {
    return false;
  }

  const encodedPayload = raw.slice(0, dotIndex);
  const signature = raw.slice(dotIndex + 1);

  const expectedSignature = await hmacSha256Hex(
    getTokenSecret(),
    encodedPayload,
  );

  if (!timingSafeEqual(signature, expectedSignature)) {
    return false;
  }

  let payload: Record<string, unknown>;

  try {
    payload = JSON.parse(
      base64UrlDecode(encodedPayload),
    ) as Record<string, unknown>;
  } catch {
    return false;
  }

  if (payload.role !== "admin") {
    return false;
  }

  const exp = Number(payload.exp || 0);

  if (!exp || exp <= Date.now()) {
    return false;
  }

  return true;
}

// Trích token admin từ body hoặc header Authorization: Bearer <token>
function extractAdminToken(
  request: Request,
  body: Record<string, unknown>,
): string {
  const fromBody = String(
    body.adminToken || "",
  ).trim();

  if (fromBody) {
    return fromBody;
  }

  const authHeader = String(
    request.headers.get("authorization") || "",
  ).trim();

  const match = authHeader.match(/^Bearer\s+(.+)$/i);

  return match ? match[1].trim() : "";
}

async function dbRequest(
  resource: string,
  init: RequestInit = {},
) {
  const { supabaseUrl, serviceRoleKey } =
    getServerConfig();

  const headers = new Headers(init.headers || {});

  headers.set("apikey", serviceRoleKey);
  headers.set(
    "Authorization",
    `Bearer ${serviceRoleKey}`,
  );

  if (
    init.body !== undefined &&
    !headers.has("Content-Type")
  ) {
    headers.set(
      "Content-Type",
      "application/json",
    );
  }

  const response = await fetch(
    `${supabaseUrl}/rest/v1/${resource}`,
    {
      ...init,
      headers,
    },
  );

  const raw = await response.text();
  let data: unknown = null;

  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = raw;
    }
  }

  if (!response.ok) {
    console.error("DATABASE_REQUEST_FAILED", {
      status: response.status,
      resource,
      data,
    });

    const error = new Error(
      "DATABASE_REQUEST_FAILED",
    ) as Error & {
      status?: number;
      details?: unknown;
    };

    error.status = response.status;
    error.details = data;
    throw error;
  }

  return {
    data,
    headers: response.headers,
  };
}

function readCount(headers: Headers) {
  const value =
    headers.get("content-range") || "";

  const match =
    value.match(/\/(\d+|\*)$/);

  if (!match || match[1] === "*") {
    return 0;
  }

  return Number(match[1]) || 0;
}

// Lấy IP client từ header do proxy gắn.
//
// CẢNH BÁO BẢO MẬT (đã từng là lỗ hổng): request gọi THẲNG vào Supabase Edge
// Function (không qua Cloudflare của bạn) nên "cf-connecting-ip" thường KHÔNG
// tồn tại trong luồng thật. Trước đây code lấy phần tử ĐẦU của
// "x-forwarded-for" — nhưng header này client tự set được (KHÔNG nằm trong
// danh sách forbidden header của trình duyệt/fetch), nên ai gọi thẳng API
// bằng script đều có thể tự chèn một IP giả bất kỳ ở đầu chuỗi để né hoàn
// toàn mọi giới hạn theo IP (session/giờ, 5 key/IP/ngày).
//
// Quy ước chuẩn: mỗi proxy khi CHUYỂN TIẾP request sẽ NỐI THÊM IP nó nhận
// được vào CUỐI chuỗi x-forwarded-for hiện có (không ghi đè). Vì vậy nếu chỉ
// có đúng 1 lớp proxy đáng tin cậy đứng trước hàm này (hạ tầng Edge Function
// của Supabase), thì phần tử CUỐI CÙNG mới là giá trị do hạ tầng tự gắn,
// client không thể chèn thêm gì sau nó. Phần tử đầu/giữa có thể là giá trị
// client tự bịa ra và PHẢI bỏ qua.
//
// Đây vẫn là best-effort (không phải danh tính tuyệt đối). Để chắc chắn hơn,
// nên đặt domain ẩn sau Cloudflare (proxy cam bật) rồi ưu tiên
// "cf-connecting-ip" — header này Cloudflare luôn ghi đè, client không giả
// được dù có tự gửi header trùng tên.
function getClientIp(request: Request): string {
  const cfIp = String(
    request.headers.get("cf-connecting-ip") || "",
  ).trim();

  if (cfIp) {
    return cfIp;
  }

  const forwarded = String(
    request.headers.get("x-forwarded-for") || "",
  ).trim();

  if (forwarded) {
    const parts = forwarded
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);

    // Lấy phần tử CUỐI (do proxy tin cậy gần nhất tự gắn), KHÔNG lấy phần tử
    // đầu (client có thể tự chèn để giả IP).
    const trusted = parts[parts.length - 1];

    if (trusted) {
      return trusted;
    }
  }

  return String(
    request.headers.get("x-real-ip") || "",
  ).trim();
}

// Xác thực Cloudflare Turnstile token với siteverify.
//
// SỬA LỖ HỔNG: trước đây khi CHƯA cấu hình TURNSTILE_SECRET_KEY, hàm này
// fail-open (trả true = không chặn gì cả). Kết hợp với việc IP có thể bị giả
// mạo (xem getClientIp ở trên), điều này khiến bất kỳ ai cũng gọi thẳng
// "create-session" bằng script, không cần trình duyệt/người thật, không cần
// vượt link — đây chính là nguyên nhân bị lấy nhiều key trong cùng khung giờ.
//
// Mặc định BÂY GIỜ là FAIL-CLOSED: nếu chưa đặt TURNSTILE_SECRET_KEY thì
// CHẶN LUÔN action "create-session" (báo lỗi rõ ràng để admin biết mà cấu
// hình), thay vì âm thầm cho qua.
//
// Nếu vì lý do nào đó bạn CHỦ ĐỘNG muốn tắt Turnstile tạm thời (ví dụ đang
// test), đặt biến môi trường TURNSTILE_REQUIRE = "false". Mặc định (không đặt
// biến này, hoặc đặt khác "false") = BẮT BUỘC phải cấu hình Turnstile.
async function verifyTurnstile(
  token: string,
  ip: string,
): Promise<boolean> {
  const secret = String(
    Deno.env.get("TURNSTILE_SECRET_KEY") || "",
  ).trim();

  const turnstileRequired =
    String(Deno.env.get("TURNSTILE_REQUIRE") || "")
      .trim()
      .toLowerCase() !== "false";

  if (!secret) {
    if (turnstileRequired) {
      console.error(
        "TURNSTILE_SECRET_KEY_NOT_SET_BLOCKING_CREATE_SESSION",
      );
      return false;
    }

    console.warn(
      "TURNSTILE_SECRET_KEY_NOT_SET_ALLOWING_BECAUSE_TURNSTILE_REQUIRE_FALSE",
    );
    return true;
  }

  const cleanToken = String(token || "").trim();

  if (!cleanToken) {
    return false;
  }

  try {
    const form = new URLSearchParams();
    form.set("secret", secret);
    form.set("response", cleanToken);

    if (ip) {
      form.set("remoteip", ip);
    }

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },
        body: form.toString(),
      },
    );

    const data = (await response.json()) as {
      success?: boolean;
    };

    return data.success === true;
  } catch (error) {
    console.error("TURNSTILE_VERIFY_ERROR", error);
    return false;
  }
}

async function countKeys(
  status: "available" | "claimed" | "disabled",
) {
  const params = new URLSearchParams({
    select: "id",
    status: `eq.${status}`,
    limit: "1",
  });

  const result = await dbRequest(
    `keys?${params.toString()}`,
    {
      method: "GET",
      headers: {
        Prefer: "count=exact",
        Range: "0-0",
      },
    },
  );

  return readCount(result.headers);
}

async function readStats() {
  const [available, claimed, disabled] =
    await Promise.all([
      countKeys("available"),
      countKeys("claimed"),
      countKeys("disabled"),
    ]);

  return {
    stats: {
      available,
      claimed,
      disabled,
    },
    total:
      available +
      claimed +
      disabled,
  };
}

async function readSettings() {
  const params = new URLSearchParams({
    select:
      "download_ipa_url,telegram_url,support_url,announcement_text,announcement_enabled,announcement_updated_at,updated_at",
    id: "eq.1",
    limit: "1",
  });

  const result = await dbRequest(
    `site_settings?${params.toString()}`,
  );

  const rows =
    Array.isArray(result.data)
      ? result.data
      : [];

  const row =
    (rows[0] || {}) as
      Record<string, unknown>;

  return {
    downloadIpaUrl:
      String(row.download_ipa_url || ""),

    telegramUrl:
      String(row.telegram_url || ""),

    supportUrl:
      String(row.support_url || ""),

    // Thông báo nổi hiển thị cho user (công khai).
    announcementText:
      String(row.announcement_text || ""),

    announcementEnabled:
      row.announcement_enabled === true,

    announcementUpdatedAt:
      row.announcement_updated_at || null,

    updatedAt:
      row.updated_at || null,
  };
}

// Đọc settings cho ADMIN: gồm cả link nút + cấu hình rút gọn (có API key).
// KHÔNG dùng cho get-settings công khai để tránh lộ API key.
async function readAdminSettings() {
  const params = new URLSearchParams({
    select:
      "download_ipa_url,telegram_url,support_url,shortener_layers,shorteners,announcement_text,announcement_enabled,announcement_updated_at,updated_at",
    id: "eq.1",
    limit: "1",
  });

  const result = await dbRequest(
    `site_settings?${params.toString()}`,
  );

  const rows =
    Array.isArray(result.data)
      ? result.data
      : [];

  const row =
    (rows[0] || {}) as
      Record<string, unknown>;

  const layersRaw =
    Number(row.shortener_layers);

  const layers =
    Number.isFinite(layersRaw)
      ? Math.min(6, Math.max(1, Math.round(layersRaw)))
      : 2;

  return {
    downloadIpaUrl:
      String(row.download_ipa_url || ""),

    telegramUrl:
      String(row.telegram_url || ""),

    supportUrl:
      String(row.support_url || ""),

    shortenerLayers: layers,

    shorteners:
      normalizeShorteners(row.shorteners),

    // Thông báo nổi (admin cấu hình).
    announcementText:
      String(row.announcement_text || ""),

    announcementEnabled:
      row.announcement_enabled === true,

    announcementUpdatedAt:
      row.announcement_updated_at || null,

    updatedAt:
      row.updated_at || null,
  };
}

// Chuẩn hóa danh sách web rút gọn từ DB / từ admin gửi lên.
// Mỗi phần tử: { name, apiUrl, apiKey, enabled }. Bỏ phần tử không hợp lệ.
// enabled = API có được dùng để rút gọn hay không (thư viện bật/tắt).
function normalizeShorteners(input: unknown) {
  let list: unknown = input;

  if (typeof input === "string") {
    try {
      list = JSON.parse(input);
    } catch {
      list = [];
    }
  }

  if (!Array.isArray(list)) {
    return [] as Array<{
      name: string;
      apiUrl: string;
      apiKey: string;
      enabled: boolean;
    }>;
  }

  const result: Array<{
    name: string;
    apiUrl: string;
    apiKey: string;
    enabled: boolean;
  }> = [];

  for (const item of list) {
    const obj =
      (item || {}) as Record<string, unknown>;

    const apiUrl =
      String(obj.apiUrl || "").trim();

    const apiKey =
      String(obj.apiKey || "").trim();

    if (!apiUrl || !apiKey) {
      continue;
    }

    let parsed: URL;

    try {
      parsed = new URL(apiUrl);
    } catch {
      continue;
    }

    if (
      !["http:", "https:"]
        .includes(parsed.protocol)
    ) {
      continue;
    }

    // Mặc định bật; chỉ tắt khi enabled === false (tương thích dữ liệu cũ).
    const enabled =
      obj.enabled === false ? false : true;

    result.push({
      name:
        String(obj.name || "")
          .trim()
          .slice(0, 60),
      apiUrl,
      apiKey,
      enabled,
    });

    if (result.length >= 10) {
      break;
    }
  }

  return result;
}

function normalizeKeys(input: unknown) {
  const source =
    Array.isArray(input)
      ? input.map(String)
      : String(input || "")
          .split(/\r?\n|,/);

  return Array.from(
    new Set(
      source
        .map((value) => value.trim())
        .filter(
          (value) =>
            value.length > 0 &&
            value.length <= 500,
        ),
    ),
  ).slice(0, 5000);
}

function normalizeUuidList(input: unknown) {
  if (!Array.isArray(input)) {
    return [];
  }

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  return Array.from(
    new Set(
      input
        .map(String)
        .map((value) => value.trim())
        .filter(
          (value) =>
            uuidPattern.test(value),
        ),
    ),
  ).slice(0, 200);
}

function normalizeOptionalUrl(input: unknown) {
  const value =
    String(input || "").trim();

  if (!value) {
    return "";
  }

  if (value.length > 2048) {
    throw new Error(
      "INVALID_SETTINGS_URL",
    );
  }

  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      "INVALID_SETTINGS_URL",
    );
  }

  if (
    !["http:", "https:"]
      .includes(parsed.protocol)
  ) {
    throw new Error(
      "INVALID_SETTINGS_URL",
    );
  }

  return parsed.toString();
}

function isUsableShortUrl(
  value: unknown,
  destinationUrl: string,
  fallbackUrl: string,
) {
  if (typeof value !== "string") {
    return false;
  }

  const text = value.trim();

  if (!/^https?:\/\//i.test(text)) {
    return false;
  }

  if (
    text === destinationUrl ||
    text === fallbackUrl
  ) {
    return false;
  }

  try {
    const candidate = new URL(text);
    const destination =
      new URL(destinationUrl);

    return !(
      candidate.hostname ===
        destination.hostname &&
      candidate.pathname ===
        destination.pathname
    );
  } catch {
    return false;
  }
}

function extractShortUrl(
  input: unknown,
  destinationUrl: string,
  fallbackUrl: string,
) {
  const priorityKeys = [
    "short_url",
    "shorturl",
    "shortUrl",
    "shortened_url",
    "shortenedUrl",
    "short_link",
    "shortLink",
    "link",
    "url",
  ];

  function walk(
    value: unknown,
    depth = 0,
  ): string {
    if (
      depth > 6 ||
      value === null ||
      value === undefined
    ) {
      return "";
    }

    if (
      isUsableShortUrl(
        value,
        destinationUrl,
        fallbackUrl,
      )
    ) {
      return String(value).trim();
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        const found =
          walk(item, depth + 1);

        if (found) {
          return found;
        }
      }

      return "";
    }

    if (typeof value === "object") {
      const record =
        value as
          Record<string, unknown>;

      for (const key of priorityKeys) {
        if (key in record) {
          const found =
            walk(
              record[key],
              depth + 1,
            );

          if (found) {
            return found;
          }
        }
      }

      for (
        const child
        of Object.values(record)
      ) {
        const found =
          walk(child, depth + 1);

        if (found) {
          return found;
        }
      }
    }

    return "";
  }

  return walk(input);
}

async function createTrafficVnLink(
  destinationUrl: string,
  apiKey: string,
  step: string,
  apiUrlOverride?: string,
) {
  const apiUrl =
    String(apiUrlOverride || "").trim() ||
    Deno.env.get(
      "TRAFFICVN_API_URL",
    ) ||
    "https://trafficvn.com/api";

  const fallbackUrl =
    Deno.env.get(
      "TRAFFICVN_FALLBACK_URL",
    ) ||
    "http://getkeyfree.unaux.com/index.html";

  if (!apiKey) {
    throw new Error(
      `SHORTENER_${step}_NOT_CONFIGURED`,
    );
  }

  const requestUrl =
    new URL(apiUrl);

  requestUrl.searchParams.set(
    "api",
    apiKey,
  );

  requestUrl.searchParams.set(
    "url",
    destinationUrl,
  );

  requestUrl.searchParams.set(
    "fallback_url",
    fallbackUrl,
  );

  let response: Response;

  try {
    response = await fetch(
      requestUrl.toString(),
      {
        method: "GET",
        headers: {
          Accept:
            "application/json, text/plain, */*",
        },
        redirect: "follow",
      },
    );
  } catch (error) {
    console.error(
      `TRAFFICVN_${step}_FETCH_ERROR`,
      error,
    );

    const err = new Error(
      `SHORTENER_${step}_REQUEST_FAILED`,
    ) as Error & { detail?: string };

    err.detail =
      `fetch_error: ${
        error instanceof Error
          ? error.message
          : String(error)
      } | endpoint=${requestUrl.origin}${requestUrl.pathname}`;

    throw err;
  }

  const raw =
    await response.text();

  if (!response.ok) {
    console.error(
      `TRAFFICVN_${step}_HTTP_ERROR`,
      response.status,
      raw.slice(0, 1000),
    );

    const err = new Error(
      `SHORTENER_${step}_REQUEST_FAILED`,
    ) as Error & { detail?: string };

    err.detail =
      `http_${response.status}: ${raw.slice(0, 300)}`;

    throw err;
  }

  let parsed: unknown =
    raw.trim();

  try {
    parsed = JSON.parse(raw);
  } catch {
    // TrafficVN có thể trả URL dạng text.
  }

  let shortUrl =
    extractShortUrl(
      parsed,
      destinationUrl,
      fallbackUrl,
    );

  if (!shortUrl) {
    const urls =
      raw.match(
        /https?:\/\/[^\s"'<>\\]+/gi,
      ) || [];

    for (const url of urls) {
      if (
        isUsableShortUrl(
          url,
          destinationUrl,
          fallbackUrl,
        )
      ) {
        shortUrl = url;
        break;
      }
    }
  }

  if (!shortUrl) {
    console.error(
      `TRAFFICVN_${step}_INVALID_RESPONSE`,
      raw.slice(0, 1500),
    );

    const err = new Error(
      `SHORTENER_${step}_INVALID_RESPONSE`,
    ) as Error & { detail?: string };

    err.detail =
      `no_valid_url_in_response: ${raw.slice(0, 300)}`;

    throw err;
  }

  return shortUrl;
}

// Fallback (tương thích ngược): dùng env key1/key2, 2 lớp như cũ.
async function createDoubleShortUrl(
  destinationUrl: string,
) {
  const legacyKey =
    String(
      Deno.env.get(
        "TRAFFICVN_API_KEY",
      ) || "",
    ).trim();

  const key1 =
    String(
      Deno.env.get(
        "TRAFFICVN_API_KEY_1",
      ) || legacyKey,
    ).trim();

  const key2 =
    String(
      Deno.env.get(
        "TRAFFICVN_API_KEY_2",
      ) || legacyKey,
    ).trim();

  if (!key1 || !key2) {
    throw new Error(
      "SHORTENER_NOT_CONFIGURED",
    );
  }

  const innerUrl =
    await createTrafficVnLink(
      destinationUrl,
      key2,
      "STEP_2",
    );

  const outerUrl =
    await createTrafficVnLink(
      innerUrl,
      key1,
      "STEP_1",
    );

  return {
    innerUrl,
    outerUrl,
  };
}

// Rút gọn nhiều lớp, luân phiên theo danh sách web (provider).
// - providers: [{ name, apiUrl, apiKey }, ...] do admin cấu hình.
// - layers: số lớp muốn rút gọn (1..6).
// - Lớp k dùng provider[(k-1) % providers.length] => web1, web2, web1...
// - Nếu 1 lớp lỗi thì BỎ QUA, giữ link đã rút được, chạy tiếp lớp sau.
// - Nếu không cấu hình provider nào => fallback về createDoubleShortUrl (env).
async function createLayeredShortUrl(
  destinationUrl: string,
  providers: Array<{
    name?: string;
    apiUrl: string;
    apiKey: string;
    enabled?: boolean;
  }>,
  layers: number,
) {
  // Chỉ dùng web đang BẬT (enabled !== false) và có đủ apiUrl + apiKey.
  const usable =
    (providers || []).filter(
      (p) =>
        p &&
        p.enabled !== false &&
        String(p.apiKey || "").trim() &&
        String(p.apiUrl || "").trim(),
    );

  // Chưa cấu hình web nào => giữ hành vi cũ (env, 2 lớp).
  if (usable.length === 0) {
    const links =
      await createDoubleShortUrl(
        destinationUrl,
      );

    return {
      outerUrl: links.outerUrl,
      layersDone: 2,
    };
  }

  const totalLayers =
    Math.min(
      6,
      Math.max(
        1,
        Math.floor(Number(layers) || 1),
      ),
    );

  let currentUrl = destinationUrl;
  let layersDone = 0;

  // Giữ lỗi lớp gần nhất để khi TẤT CẢ lớp fail thì báo lý do thật ra ngoài.
  let lastError:
    | (Error & { detail?: string })
    | null = null;

  for (let k = 1; k <= totalLayers; k += 1) {
    const provider =
      usable[(k - 1) % usable.length];

    try {
      currentUrl =
        await createTrafficVnLink(
          currentUrl,
          String(provider.apiKey).trim(),
          `LAYER_${k}`,
          String(provider.apiUrl).trim(),
        );

      layersDone += 1;
    } catch (error) {
      // Bỏ qua lớp lỗi, dùng link đã rút được.
      lastError =
        error instanceof Error
          ? error
          : new Error(String(error));

      console.error(
        `SHORTENER_LAYER_${k}_SKIPPED`,
        (provider.name || provider.apiUrl),
        lastError.message,
        (lastError as Error & { detail?: string })
          .detail || "",
      );
    }
  }

  // Không lớp nào thành công => coi như thất bại toàn bộ.
  if (layersDone === 0) {
    const err = new Error(
      "SHORTENER_ALL_FAILED",
    ) as Error & { detail?: string };

    if (lastError) {
      err.detail =
        lastError.detail ||
        lastError.message;
    }

    throw err;
  }

  return {
    outerUrl: currentUrl,
    layersDone,
  };
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  if (request.method !== "POST") {
    return jsonResponse(
      {
        success: false,
        error: "METHOD_NOT_ALLOWED",
        version: KEY_API_VERSION,
      },
      405,
    );
  }

  try {
    const body =
      await request
        .json()
        .catch(() => ({}));

    const action =
      String(
        body.action || "",
      ).trim();

    if (action === "version") {
      return jsonResponse({
        success: true,
        version: KEY_API_VERSION,
      });
    }

    if (action === "get-settings") {
      return jsonResponse({
        success: true,
        version: KEY_API_VERSION,
        settings:
          await readSettings(),
      });
    }

    if (action === "count") {
      return jsonResponse({
        success: true,
        version: KEY_API_VERSION,
        count:
          await countKeys(
            "available",
          ),
      });
    }

    if (action === "create-session") {
      const keyPageUrl =
        String(
          Deno.env.get(
            "KEY_PAGE_URL",
          ) || "",
        ).trim();

      if (!keyPageUrl) {
        return jsonResponse(
          {
            success: false,
            error:
              "SHORTENER_NOT_CONFIGURED",
            version: KEY_API_VERSION,
          },
          500,
        );
      }

      if (
        await countKeys("available")
        <= 0
      ) {
        return jsonResponse(
          {
            success: false,
            error: "OUT_OF_KEYS",
            version: KEY_API_VERSION,
          },
          409,
        );
      }

      // IP thật của người tạo phiên (server tự đọc, không tin client).
      const creatorIp = getClientIp(request);

      // LỚP 1 — Cloudflare Turnstile: chặn bot/script.
      // LUÔN kiểm tra (kể cả khi chưa cấu hình secret) — verifyTurnstile() tự
      // quyết định fail-open/fail-closed dựa trên TURNSTILE_REQUIRE. Trước
      // đây code chỉ gọi verifyTurnstile khi ĐÃ có secret, nên lúc chưa cấu
      // hình thì lớp 1 coi như không tồn tại — đây là một phần nguyên nhân
      // gây lạm dụng.
      const turnstileToken =
        String(
          body.turnstileToken || "",
        ).trim();

      const turnstileOk =
        await verifyTurnstile(
          turnstileToken,
          creatorIp,
        );

      if (!turnstileOk) {
        return jsonResponse(
          {
            success: false,
            error: "CAPTCHA_FAILED",
            version: KEY_API_VERSION,
          },
          403,
        );
      }

      // LỚP 2 — Hạn chế số session/IP/giờ (chống đốt quota rút gọn + phình
      // bảng session). Atomic trong DB. Mặc định 30/giờ.
      try {
        const bump =
          await dbRequest(
            "rpc/bump_session_limit",
            {
              method: "POST",
              body: JSON.stringify({
                p_ip: creatorIp,
                p_max: 30,
              }),
            },
          );

        // RPC trả table(allowed, current_count) => PostgREST cho mảng
        // [{allowed: true, current_count: 1}]. Đọc đúng field .allowed.
        const bumpRow =
          Array.isArray(bump.data)
            ? (bump.data[0] as Record<string, unknown> | undefined)
            : (bump.data as Record<string, unknown> | null);

        const allowed =
          !bumpRow || bumpRow.allowed === true;

        if (!allowed) {
          return jsonResponse(
            {
              success: false,
              error: "SESSION_RATE_LIMITED",
              version: KEY_API_VERSION,
            },
            429,
          );
        }
      } catch (error) {
        // RPC chưa tồn tại / lỗi DB: không chặn tạo session, chỉ log.
        console.error(
          "BUMP_SESSION_LIMIT_FAILED",
          error,
        );
      }

      const insertResult =
        await dbRequest(
          "key_sessions?select=token,expires_at",
          {
            method: "POST",
            headers: {
              Prefer:
                "return=representation",
            },
            body: JSON.stringify({
              creator_ip: creatorIp,
            }),
          },
        );

      const sessionRows =
        Array.isArray(
          insertResult.data,
        )
          ? insertResult.data
          : [];

      const session = (sessionRows[0] || {}) as Record<string, unknown>;

      const token =
        String(
          session.token || "",
        );

      if (!token) {
        return jsonResponse(
          {
            success: false,
            error:
              "CREATE_SESSION_FAILED",
            version: KEY_API_VERSION,
          },
          500,
        );
      }

      try {
        // Dựng URL đích dạng /k/{mã}. Mã = token UUID bỏ hết dấu gạch
        // (32 ký tự hex) cho gọn giống link mẫu getkey.../k/<hash>.
        // Lấy origin từ KEY_PAGE_URL nên KHÔNG cần đổi biến môi trường.
        const base = new URL(keyPageUrl);
        const code = token.replace(/-/g, "");
        const destination = new URL(
          `/k/${code}`,
          base.origin,
        );

        // Đọc cấu hình rút gọn do admin lưu (danh sách web + số lớp).
        const adminSettings =
          await readAdminSettings();

        const links =
          await createLayeredShortUrl(
            destination.toString(),
            adminSettings.shorteners,
            adminSettings.shortenerLayers,
          );

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          token,
          expiresAt:
            session.expires_at || null,
          shortUrl:
            links.outerUrl,
          shortenerLayers:
            links.layersDone,
        });
      } catch (error) {
        const params =
          new URLSearchParams({
            token: `eq.${token}`,
          });

        await dbRequest(
          `key_sessions?${params.toString()}`,
          {
            method: "DELETE",
          },
        ).catch(() => undefined);

        const code =
          error instanceof Error
            ? error.message
            : "SHORTENER_REQUEST_FAILED";

        const detail =
          (error as Error & { detail?: string })
            .detail || null;

        return jsonResponse(
          {
            success: false,
            error: code,
            detail,
            version: KEY_API_VERSION,
          },
          502,
        );
      }
    }

    if (action === "claim") {
      const token =
        String(
          body.token || "",
        ).trim();

      if (!token) {
        return jsonResponse(
          {
            success: false,
            error: "TOKEN_REQUIRED",
            version: KEY_API_VERSION,
          },
          400,
        );
      }

      // Danh tính để đếm hạn mức: IP (do proxy Supabase gắn) + device ID
      // (client gửi từ localStorage). Cả hai đều do client kiểm soát nên đây
      // là chống lạm dụng best-effort, không phải chặn tuyệt đối.
      const clientIp = getClientIp(request);
      const deviceId =
        String(
          body.deviceId || "",
        ).trim();

      try {
        const result =
          await dbRequest(
            "rpc/claim_key_limited",
            {
              method: "POST",
              body: JSON.stringify({
                p_token: token,
                p_ip: clientIp,
                p_device_id: deviceId,
              }),
            },
          );

        const rows =
          Array.isArray(result.data)
            ? result.data
            : [];

        const row = (rows[0] || {}) as Record<string, unknown>;

        const key =
          String(
            row.key_value || "",
          );

        if (!key) {
          throw new Error(
            "KEY_NOT_FOUND",
          );
        }

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          key,
        });
      } catch (error) {
        const details =
          JSON.stringify(
            (
              error as Error & {
                details?: unknown;
              }
            ).details || "",
          );

        let code =
          error instanceof Error
            ? error.message
            : "CLAIM_FAILED";

        for (
          const candidate
          of [
            "INVALID_SESSION",
            "SESSION_EXPIRED",
            "OUT_OF_KEYS",
            "KEY_NOT_FOUND",
            "LIMIT_REACHED",
            "TOKEN_IP_MISMATCH",
          ]
        ) {
          if (
            details.includes(
              candidate,
            )
          ) {
            code = candidate;
          }
        }

        return jsonResponse(
          {
            success: false,
            error: code,
            version: KEY_API_VERSION,
          },
          400,
        );
      }
    }

    // Đăng nhập admin: đổi mật khẩu lấy token có chữ ký HMAC.
    if (action === "admin-login") {
      const adminPassword = readAdminPassword();

      // Chưa cấu hình mật khẩu = chặn hoàn toàn, không cho vào.
      if (!adminPassword || adminPassword.length < 8) {
        console.error("ADMIN_PASSWORD_NOT_CONFIGURED");

        return jsonResponse(
          {
            success: false,
            error: "ADMIN_PASSWORD_NOT_CONFIGURED",
            version: KEY_API_VERSION,
          },
          503,
        );
      }

      const submitted = String(body.password || "");

      if (!timingSafeEqual(submitted, adminPassword)) {
        return jsonResponse(
          {
            success: false,
            error: "INVALID_CREDENTIALS",
            version: KEY_API_VERSION,
          },
          401,
        );
      }

      const adminToken = await issueAdminToken();

      const [stats, settings] = await Promise.all([
        readStats(),
        readAdminSettings(),
      ]);

      return jsonResponse({
        success: true,
        authenticated: true,
        version: KEY_API_VERSION,
        adminToken,
        expiresInMs: ADMIN_TOKEN_TTL_MS,
        ...stats,
        settings,
      });
    }

    const adminActions = [
      "admin-stats",
      "admin-update-settings",
      "admin-add-keys",
      "admin-list-keys",
      "admin-delete-keys",
      "admin-update-status",
      "admin-refresh",
    ];

    if (
      adminActions.includes(action)
    ) {
      // GATE: mọi hành động quản trị đều phải có token hợp lệ.
      const adminToken = extractAdminToken(request, body);

      if (!(await verifyAdminToken(adminToken))) {
        return jsonResponse(
          {
            success: false,
            error: "UNAUTHORIZED",
            version: KEY_API_VERSION,
          },
          401,
        );
      }

      // Trả toàn bộ dữ liệu dashboard trong 1 lần (dùng khi mở lại trang).
      if (action === "admin-refresh") {
        const [stats, settings] = await Promise.all([
          readStats(),
          readAdminSettings(),
        ]);

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          ...stats,
          settings,
        });
      }

      if (
        action === "admin-stats"
      ) {
        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          ...(await readStats()),
        });
      }

      if (
        action ===
          "admin-update-settings"
      ) {
        let downloadIpaUrl = "";
        let telegramUrl = "";
        let supportUrl = "";

        try {
          downloadIpaUrl =
            normalizeOptionalUrl(
              body.downloadIpaUrl,
            );

          telegramUrl =
            normalizeOptionalUrl(
              body.telegramUrl,
            );

          supportUrl =
            normalizeOptionalUrl(
              body.supportUrl,
            );
        } catch {
          return jsonResponse(
            {
              success: false,
              error:
                "INVALID_SETTINGS_URL",
              version:
                KEY_API_VERSION,
            },
            400,
          );
        }

        // Cấu hình rút gọn: số lớp (1..6) + danh sách web.
        const shortenerLayers =
          Math.min(
            6,
            Math.max(
              1,
              Math.floor(
                Number(body.shortenerLayers) || 2,
              ),
            ),
          );

        const shorteners =
          normalizeShorteners(body.shorteners);

        // Thông báo nổi: nội dung (tối đa 500 ký tự) + bật/tắt.
        const announcementText =
          String(body.announcementText || "")
            .trim()
            .slice(0, 500);

        const announcementEnabled =
          body.announcementEnabled === true;

        const result =
          await dbRequest(
            "site_settings?on_conflict=id&select=download_ipa_url,telegram_url,support_url,shortener_layers,shorteners,announcement_text,announcement_enabled,announcement_updated_at,updated_at",
            {
              method: "POST",
              headers: {
                Prefer:
                  "resolution=merge-duplicates,return=representation",
              },
              body: JSON.stringify({
                id: 1,
                download_ipa_url:
                  downloadIpaUrl,
                telegram_url:
                  telegramUrl,
                support_url:
                  supportUrl,
                shortener_layers:
                  shortenerLayers,
                shorteners,
                announcement_text:
                  announcementText,
                announcement_enabled:
                  announcementEnabled,
                announcement_updated_at:
                  new Date()
                    .toISOString(),
                updated_at:
                  new Date()
                    .toISOString(),
              }),
            },
          );

        const rows =
          Array.isArray(result.data)
            ? result.data
            : [];

        const row = (rows[0] || {}) as Record<string, unknown>;

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          settings: {
            downloadIpaUrl:
              row.download_ipa_url || "",
            telegramUrl:
              row.telegram_url || "",
            supportUrl:
              row.support_url || "",
            shortenerLayers:
              Number(row.shortener_layers) || shortenerLayers,
            shorteners:
              normalizeShorteners(row.shorteners),
            announcementText:
              String(row.announcement_text || ""),
            announcementEnabled:
              row.announcement_enabled === true,
            announcementUpdatedAt:
              row.announcement_updated_at || null,
            updatedAt:
              row.updated_at || null,
          },
        });
      }

      if (
        action ===
          "admin-add-keys"
      ) {
        const keys =
          normalizeKeys(body.keys);

        if (!keys.length) {
          return jsonResponse(
            {
              success: false,
              error:
                "NO_KEYS_PROVIDED",
              version:
                KEY_API_VERSION,
            },
            400,
          );
        }

        const result =
          await dbRequest(
            "keys?on_conflict=key_value&select=id",
            {
              method: "POST",
              headers: {
                Prefer:
                  "resolution=ignore-duplicates,return=representation",
              },
              body: JSON.stringify(
                keys.map(
                  (keyValue) => ({
                    key_value:
                      keyValue,
                    status:
                      "available",
                  }),
                ),
              ),
            },
          );

        const inserted =
          Array.isArray(result.data)
            ? result.data.length
            : 0;

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          inserted,
          duplicates:
            Math.max(
              0,
              keys.length - inserted,
            ),
        });
      }

      if (
        action ===
          "admin-list-keys"
      ) {
        const page =
          Math.max(
            1,
            Math.floor(
              Number(body.page) || 1,
            ),
          );

        const pageSize =
          Math.min(
            100,
            Math.max(
              10,
              Math.floor(
                Number(
                  body.pageSize,
                ) || 50,
              ),
            ),
          );

        const search =
          String(
            body.search || "",
          )
            .trim()
            .slice(0, 150);

        const status =
          String(
            body.status || "",
          ).trim();

        const params =
          new URLSearchParams({
            select:
              "id,key_value,status,created_at,claimed_at",
            order:
              "created_at.desc",
            offset:
              String(
                (page - 1) *
                  pageSize,
              ),
            limit:
              String(pageSize),
          });

        if (
          [
            "available",
            "claimed",
            "disabled",
          ].includes(status)
        ) {
          params.set(
            "status",
            `eq.${status}`,
          );
        }

        if (search) {
          params.set(
            "key_value",
            `ilike.*${search}*`,
          );
        }

        const result =
          await dbRequest(
            `keys?${params.toString()}`,
            {
              method: "GET",
              headers: {
                Prefer:
                  "count=exact",
              },
            },
          );

        const total =
          readCount(result.headers);

        const rows =
          Array.isArray(result.data)
            ? result.data
            : [];

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,

          keys:
            rows.map((item) => {
              const row =
                item as
                  Record<string, unknown>;

              return {
                id: row.id,
                keyValue:
                  row.key_value,
                status:
                  row.status,
                createdAt:
                  row.created_at,
                claimedAt:
                  row.claimed_at,
              };
            }),

          pagination: {
            page,
            pageSize,
            total,
            totalPages:
              Math.max(
                1,
                Math.ceil(
                  total / pageSize,
                ),
              ),
          },
        });
      }

      if (
        action ===
          "admin-delete-keys"
      ) {
        const keyIds =
          normalizeUuidList(
            body.keyIds,
          );

        if (!keyIds.length) {
          return jsonResponse(
            {
              success: false,
              error:
                "NO_KEYS_SELECTED",
              version:
                KEY_API_VERSION,
            },
            400,
          );
        }

        const result =
          await dbRequest(
            "rpc/admin_delete_keys",
            {
              method: "POST",
              body: JSON.stringify({
                p_ids: keyIds,
              }),
            },
          );

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          deleted:
            Number(result.data) || 0,
        });
      }

      // Đổi trạng thái key: khóa (disabled), mở lại / trả về kho (available).
      if (action === "admin-update-status") {
        const keyIds = normalizeUuidList(body.keyIds);

        if (!keyIds.length) {
          return jsonResponse(
            {
              success: false,
              error: "NO_KEYS_SELECTED",
              version: KEY_API_VERSION,
            },
            400,
          );
        }

        const targetStatus = String(body.status || "").trim();

        if (
          !["available", "disabled"].includes(targetStatus)
        ) {
          return jsonResponse(
            {
              success: false,
              error: "INVALID_STATUS",
              version: KEY_API_VERSION,
            },
            400,
          );
        }

        const result = await dbRequest(
          "rpc/admin_set_key_status",
          {
            method: "POST",
            body: JSON.stringify({
              p_ids: keyIds,
              p_status: targetStatus,
            }),
          },
        );

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          updated: Number(result.data) || 0,
        });
      }
    }

    return jsonResponse(
      {
        success: false,
        error: "INVALID_ACTION",
        version: KEY_API_VERSION,
      },
      400,
    );
  } catch (error) {
    console.error(
      "KEY_API_UNHANDLED_ERROR",
      {
        version: KEY_API_VERSION,
        error,
      },
    );

    const code =
      error instanceof Error
        ? error.message
        : "INTERNAL_SERVER_ERROR";

    return jsonResponse(
      {
        success: false,
        error:
          code ===
            "SERVER_CONFIG_ERROR"
            ? code
            : "INTERNAL_SERVER_ERROR",
        version: KEY_API_VERSION,
      },
      500,
    );
  }
});
