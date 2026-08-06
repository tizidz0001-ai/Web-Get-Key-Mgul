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
  SUPABASE_PUBLISHABLE_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxrbG9ta2R5anNteGprbGt3YnV3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ3NDYyMzcsImV4cCI6MjEwMDMyMjIzN30.a_OpqtI78QzAh-E7hj777g2OZFqp4sM61bKoj8P9T_k",

  EDGE_FUNCTION_NAME: "key-api",

  // Cloudflare Turnstile SITE KEY (public, dán ở frontend được).
  // Lấy ở Cloudflare Dashboard > Turnstile > tạo widget cho domain của bạn.
  //
  // QUAN TRỌNG (đã đổi hành vi để vá lỗ hổng bị lấy nhiều key cùng lúc):
  // Server (edge function key-api) BẮT BUỘC có TURNSTILE_SECRET_KEY. V14 xác
  // minh hai action: "create-session" ở index.html và "claim-key" ở key.html.
  // Nếu thiếu secret thì cả tạo link lẫn nhận key đều bị CHẶN
  // hoàn toàn (trả lỗi CAPTCHA_FAILED cho mọi người, kể cả người dùng thật).
  // => Phải điền SITE_KEY ở đây VÀ đặt SECRET_KEY tương ứng trong Supabase
  // Edge Functions > key-api > Secrets thì trang mới hoạt động lại được.
  // (Chỉ dùng TURNSTILE_REQUIRE=false trong Supabase Secrets nếu bạn CHỦ ĐỘNG
  // muốn tạm tắt Turnstile để test — không khuyến khích dùng khi đã public.)
  TURNSTILE_SITE_KEY: "0x4AAAAAAEBdDkwtIJ79Y50E",

  // Chỉ email này có thể mở chức năng quản trị.
  ADMIN_EMAIL: "hatrungson230209@gmail.com",

  // Để trống để tự dùng đúng URL admin.html hiện tại.
  // Có thể điền: "https://hypergetkeymigul.vercel.app/"
  ADMIN_REDIRECT_URL: "",

  // Không lưu session token hoặc key đã cấp ở frontend. Hai tên dưới chỉ
  // được dùng để xóa dữ liệu còn sót từ phiên bản cũ.
  SESSION_STORAGE_KEY: "migul_key_session_token_v1",
  KEY_CACHE_STORAGE_KEY: "migul_claimed_key_cache_v1",

  // Tên cũ chỉ dùng để xóa ID localStorage của V16; V17 không còn tin giá trị này.
  DEVICE_ID_STORAGE_KEY: "migul_device_id_v1",

  // V17: khóa thiết bị ECDSA P-256 được lưu trong IndexedDB. Private key
  // được import ở chế độ non-extractable nên sửa localStorage/F12 không thể
  // giả mạo đúng ID thiết bị cũ.
  DEVICE_KEY_DB_NAME: "migul_device_keystore_v17",
  DEVICE_KEY_STORE_NAME: "device_keys",
  DEVICE_KEY_RECORD_ID: "primary_device_key",

  JOURNEY_SECRET_STORAGE_KEY: "migul_journey_secret_v14",

  DISABLE_WHEN_OUT_OF_STOCK: true
};
