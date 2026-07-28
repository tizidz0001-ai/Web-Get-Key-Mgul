window.APP_CONFIG = {
  APP_NAME: "Get Key Free Fire iPA",

  DOWNLOAD_IPA_URL: "",
  TELEGRAM_URL: "",
  SUPPORT_URL: "",

  // Project URL của Supabase.
  // Ví dụ: https://abcdefgh.supabase.co
  SUPABASE_URL: "https://lklomkdyjsmxjklkwbuw.supabase.co",

  // Publishable Key trong Supabase > Project Settings > API Keys.
  // Key này được phép đặt ở frontend. Không dùng Secret Key hoặc service_role.
  SUPABASE_PUBLISHABLE_KEY: "sb_publishable_RyrfCsP4JFU4cf_cBtF77g_GleTAOSm",

  EDGE_FUNCTION_NAME: "key-api",

  // Cloudflare Turnstile SITE KEY (public, dán ở frontend được).
  // Lấy ở Cloudflare Dashboard > Turnstile > tạo widget cho domain của bạn.
  // Để TRỐNG = tắt Turnstile (không chặn bot). Điền vào = bật bảo vệ.
  // Lưu ý: phải đặt TURNSTILE_SECRET_KEY trong Supabase Secrets để verify.
  TURNSTILE_SITE_KEY: "0x4AAAAAAD_qZgzx7LqdFqVG",

  // Chỉ email này có thể mở chức năng quản trị.
  ADMIN_EMAIL: "hatrungson230209@gmail.com",

  // Để trống để tự dùng đúng URL admin.html hiện tại.
  // Có thể điền: "http://getkeyfree.unaux.com/admin.html"
  ADMIN_REDIRECT_URL: "",

  SESSION_STORAGE_KEY: "migul_key_session_token_v1",
  KEY_CACHE_STORAGE_KEY: "migul_claimed_key_cache_v1",

  // Định danh thiết bị bền (localStorage) để giới hạn số key mỗi (IP + thiết bị).
  DEVICE_ID_STORAGE_KEY: "migul_device_id_v1",

  DISABLE_WHEN_OUT_OF_STOCK: true
};
