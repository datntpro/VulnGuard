# Đăng nhập và phân quyền

Mã nguồn: `api/routes/auth.py`, `api/security.py`, `api/auth_models.py`.

## Luồng đăng nhập

1. `GET /api/auth/status` trả `auth_enabled` và `setup_required` (true khi DB chưa có user).
2. Nếu chưa có user: `POST /api/auth/setup` tạo ADMIN đầu tiên (`email`, `name`, `password` tối thiểu 10 ký tự). Endpoint trả 409 khi đã có user.
3. `POST /api/auth/login` với `email`, `password`. Server đặt cookie `vg_session` (HttpOnly, `SameSite=Strict`, `Secure` theo `COOKIE_SECURE`, hạn `SESSION_TTL_HOURS`) và trả về `token` để dùng cho CLI/CI.
4. Mọi request `/api/*` (trừ `status`, `login`, `setup`, `logout`, `/api/health`) cần cookie hoặc header `Authorization: Bearer <token>`. Trang `/` chưa đăng nhập bị chuyển tới `/login`.

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<mật khẩu>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/auth/me
```

## Phiên và mật khẩu

- Mật khẩu băm bằng `hashlib.scrypt` (n=2^14, r=8, p=1, salt 16 byte).
- JWT HS256, ký bằng `VULNGUARD_SECRET_KEY` hoặc `storage/secret.key`. Payload có `tv` (token version) và `jti` (id phiên).
- `POST /api/auth/logout` thu hồi **đúng token đang dùng** (ghi `jti` vào bảng `revoked_tokens`, dọn các dòng đã hết hạn). Token CLI/CI khác của cùng user vẫn dùng được. Token cấp trước bản này (không có `jti`) được thu hồi bằng cách tăng `token_version`.
- `POST /api/auth/logout-all` tăng `token_version` → đăng xuất **mọi** phiên và token của user.
- WebSocket File Assistant kiểm tra phiên thật (chữ ký, `token_version`, `is_active`, vai trò hiện tại, `jti`) trước `accept()` và lại ở mỗi message; chặn Origin khác host; trả 403 khi `FEATURE_FILE_ASSISTANT=false`.
- Đổi mật khẩu, đổi vai trò, khoá tài khoản đều tăng `token_version`, làm các phiên cũ mất hiệu lực.
- `POST /api/auth/change-password` (`current_password`, `new_password` ≥ 10 ký tự, phải khác mật khẩu cũ) xoá cờ `must_change_password` và cấp phiên mới.
- Đăng nhập luôn chạy `verify_password` kể cả khi email không tồn tại để không lộ thông tin qua thời gian phản hồi.
- Chống brute-force: sau 5 lần thử sai trong 15 phút, đăng nhập trả 429 kèm `Retry-After`. Mỗi lần thử được tính **trước** khi kiểm tra mật khẩu (nguyên tử), nên request đồng thời không vượt quá 5 lần. Khoá theo **thiết bị** nếu trình duyệt có cookie `vg_device` hợp lệ của đúng user đó (HMAC với khoá phụ, ràng buộc theo user id, cấp sau mỗi lần đăng nhập đúng, `HttpOnly`, `SameSite=Strict`, path `/api/auth`, 180 ngày); mọi client còn lại của cùng một email dùng chung một bucket (không theo IP, nên xoay IP / giả `X-Forwarded-For` không tăng số lần thử). Người ngoài không có cookie chỉ khoá được bucket chung đó, không khoá được ADMIN đang dùng trình duyệt quen.
- Giới hạn đã biết: client **không có** cookie `vg_device` (CLI/CI gọi `/api/auth/login`, trình duyệt mới/ẩn danh, đã xoá cookie) vẫn có thể bị người khác khoá tạm 15 phút. Với CLI/CI: đăng nhập từ máy giữ cookie `vg_device`, hoặc tăng `SESSION_TTL_HOURS` để token dùng lại lâu hơn (chưa có API cấp token dài hạn); để khôi phục ngay, khởi động lại tiến trình (bộ đếm nằm trong bộ nhớ, tối đa 10 000 khoá, khoá đang hiệu lực không bị đẩy ra khi đầy).
- Đổi `VULNGUARD_SECRET_KEY` làm mọi cookie `vg_device` mất hiệu lực (mọi trình duyệt thành "chưa biết") và đăng xuất mọi JWT.
- uvicorn mặc định tin `X-Forwarded-For` từ 127.0.0.1. Bản native nên đặt `FORWARDED_ALLOW_IPS` đúng IP reverse proxy (hoặc rỗng nếu không dùng proxy). Reverse proxy phải giữ nguyên `Host` (`proxy_set_header Host $host`) để kiểm tra Origin của WebSocket không chặn nhầm.

## Vai trò

Kiểm tra ở `auth_middleware` theo method và tiền tố đường dẫn:

| Vai trò | Quyền |
|---|---|
| `VIEWER` | Chỉ `GET`/`HEAD`. Mọi method khác trả 403 |
| `ANALYST` | Tạo project, chạy scan, triage, waiver, domain, crawl, web scan (không fuzz), engagement (không uỷ quyền), chạy pentest, duyệt approval của người khác, SCM |
| `ADMIN` | Tất cả, cộng các mục chỉ ADMIN bên dưới |

Chỉ ADMIN (middleware `ADMIN_ONLY`):

- mọi method trên `/api/auth/users`
- `PUT /api/ai/config`
- `PUT` trên `/api/settings/*`
- `POST`/`PUT`/`DELETE` trên `/api/ollama/*`
- mọi method trên `/api/coworker/*` và `/api/connectors/*`
- `POST /api/intel/refresh`

Chỉ ADMIN (kiểm tra trong route):

- bật `authorized=true` cho engagement Pentest
- bật `fuzz=true` cho web scan
- chốt trạng thái triage `NOT_EXPLOITABLE`

Quản lý user (`/api/auth/users`): luôn phải còn ít nhất 1 ADMIN đang hoạt động; không tự xoá tài khoản đang đăng nhập.

## Khi `AUTH_ENABLED=false`

- Mọi request được coi như user giả `dev@local` với quyền **ANALYST** (không còn là ADMIN).
- Mọi route chỉ-ADMIN (`ADMIN_ONLY`), toàn bộ `/api/coworker` và `/api/file-assistant` bị chặn (403, `code: auth_required`). Co-work và File Assistant yêu cầu bật auth.
- Các method khác `GET`/`HEAD`/`OPTIONS` trên `/api/pentest`, `/api/webscans`, `/api/domains` bị chặn (403). Nghĩa là không tạo domain, crawl, web scan hay pentest được.
- Header `Host` chỉ được là `localhost`, `127.0.0.1`, `[::1]` hoặc giá trị trong `ALLOWED_HOSTS` (còn lại: 421) để chống DNS rebinding.
- Chỉ dùng cho dev 1 người trên localhost.

## CORS, CSRF và tiêu đề bảo mật

- Mặc định **same-origin**: không bật CORS. Muốn cho client trình duyệt bên thứ ba, đặt `CORS_ALLOW_ORIGINS=https://a.example,https://b.example`.
- Request ghi (`POST/PUT/PATCH/DELETE`) tới `/api/*` có `Origin` khác `Host` (và không nằm trong `CORS_ALLOW_ORIGINS`), hoặc `Sec-Fetch-Site: cross-site`, bị từ chối 403 (`bad_origin`). Request không có `Origin` (CLI/CI) vẫn được chấp nhận.
- Sau reverse proxy: proxy phải **giữ nguyên header `Host`** (cả cho WebSocket lẫn guard Origin của HTTP), nếu không mọi thao tác ghi từ trình duyệt (kể cả đăng nhập) bị 403 `bad_origin`. Cách khác: đặt `CORS_ALLOW_ORIGINS=<origin công khai>`.
- Mọi response có `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; trang HTML có CSP nền (`default-src 'self'`, `frame-ancestors 'none'`, `connect-src 'self'`). CSP nghiêm ngặt không cho inline script được hoãn lại (cần refactor các `onclick` inline).
- `/docs`, `/redoc`, `/openapi.json` yêu cầu đăng nhập (mọi role). `EXPOSE_API_DOCS=false` tắt hẳn.
- `ALLOWED_HOSTS` (csv): khi auth bật và biến này khác rỗng, chỉ chấp nhận các Host đó (cộng loopback).

## Bắt đổi mật khẩu lần đầu

Tài khoản do `scripts/bootstrap_admin.py` tạo, user do ADMIN tạo mới và user bị ADMIN đặt lại mật khẩu đều có `must_change_password=True`. API **chặn** mọi path (trừ `/api/auth/me`, `change-password`, `logout`, `logout-all`, `status`, `/api/features`, `/api/health`) bằng 403 `code: must_change_password` cho tới khi người dùng đổi mật khẩu; giao diện web hiện hộp đổi mật khẩu bắt buộc.
