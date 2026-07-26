// BẢN ADMIN CÓ XÁC THỰC MẬT KHẨU (SERVER-SIDE)
// Test bằng {"action":"version"} phải trả KEY_API_ADMIN_SECURED_V10_20260724
// KEY_API_VERSION: KEY_API_ADMIN_SECURED_V10_20260724
//
// BẮT BUỘC đặt biến môi trường (Supabase > Edge Functions > key-api > Secrets):
//   ADMIN_PASSWORD      = mật khẩu admin (tối thiểu 8 ký tự)
//   ADMIN_TOKEN_SECRET  = chuỗi bí mật ngẫu nhiên dài để ký token (tùy chọn,
//                         nếu bỏ trống sẽ tự suy ra từ ADMIN_PASSWORD + service key)

const KEY_API_VERSION = "KEY_API_ADMIN_SECURED_V10_20260724";

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
      "download_ipa_url,telegram_url,support_url,updated_at",
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

    updatedAt:
      row.updated_at || null,
  };
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
  step: "STEP_1" | "STEP_2",
) {
  const apiUrl =
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

    throw new Error(
      `SHORTENER_${step}_REQUEST_FAILED`,
    );
  }

  const raw =
    await response.text();

  if (!response.ok) {
    console.error(
      `TRAFFICVN_${step}_HTTP_ERROR`,
      response.status,
      raw.slice(0, 1000),
    );

    throw new Error(
      `SHORTENER_${step}_REQUEST_FAILED`,
    );
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

    throw new Error(
      `SHORTENER_${step}_INVALID_RESPONSE`,
    );
  }

  return shortUrl;
}

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

      const insertResult =
        await dbRequest(
          "key_sessions?select=token,expires_at",
          {
            method: "POST",
            headers: {
              Prefer:
                "return=representation",
            },
            body: JSON.stringify({}),
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
        const destination =
          new URL(keyPageUrl);

        destination.searchParams.set(
          "token",
          token,
        );

        const links =
          await createDoubleShortUrl(
            destination.toString(),
          );

        return jsonResponse({
          success: true,
          version: KEY_API_VERSION,
          token,
          expiresAt:
            session.expires_at || null,
          shortUrl:
            links.outerUrl,
          shortenerLayers: 2,
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

        return jsonResponse(
          {
            success: false,
            error: code,
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

      try {
        const result =
          await dbRequest(
            "rpc/claim_key",
            {
              method: "POST",
              body: JSON.stringify({
                p_token: token,
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
        readSettings(),
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
          readSettings(),
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

        const result =
          await dbRequest(
            "site_settings?on_conflict=id&select=download_ipa_url,telegram_url,support_url,updated_at",
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
