window.APP_CONFIG = {
  APP_NAME: "Tizi Store Get Key",

  DOWNLOAD_IPA_URL: "",
  TELEGRAM_URL: "",
  SUPPORT_URL: "",

  // Project URL của Supabase.
  // Ví dụ: https://abcdefgh.supabase.co
  SUPABASE_URL: "https://lklomkdyjsmxjklkwbuw.supabase.co",

  // Publishable Key trong Supabase > Project Settings > API Keys.
  // Key này được phép đặt ở frontend. Không dùng Secret Key hoặc service_role.
  SUPABASE_PUBLISHABLE_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxrbG9ta2R5anNteGprbGt3YnV3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ3NDYyMzcsImV4cCI6MjEwMDMyMjIzN30.a_OpqtI78QzAh-E7hj777g2OZFqp4sM61bKoj8P9T_k",

  EDGE_FUNCTION_NAME: "key-api",

  // Cloudflare Turnstile SITE KEY (public, dán ở frontend được).
  // Lấy ở Cloudflare Dashboard > Turnstile > tạo widget cho domain của bạn.
  //
  // V16: Turnstile chỉ chạy lúc người dùng bấm tạo link ở index.html.
  // Trang key không chạy challenge lần 2 để tránh lỗi Telegram/WebView.
  // Server vẫn cần TURNSTILE_SECRET_KEY để xác minh action "create-session".
  TURNSTILE_SITE_KEY: "0x4AAAAAAELiXxTlmMOtTvJL",

  // Chỉ email này có thể mở chức năng quản trị.
  ADMIN_EMAIL: "hatrungson230209@gmail.com",

  // Để trống để tự dùng đúng URL admin.html hiện tại.
  // Có thể điền: "https://hypergetkeymigul.vercel.app/"
  ADMIN_REDIRECT_URL: "",

  // Không lưu session token hoặc key đã cấp ở frontend. Hai tên dưới chỉ
  // được dùng để xóa dữ liệu còn sót từ phiên bản cũ.
  SESSION_STORAGE_KEY: "migul_key_session_token_v1",
  KEY_CACHE_STORAGE_KEY: "migul_claimed_key_cache_v1",


  DISABLE_WHEN_OUT_OF_STOCK: true
};
