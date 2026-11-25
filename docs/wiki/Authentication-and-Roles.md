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
- Giới hạn đã biết: client **không có** cookie `vg_device` (CLI/CI gọi `/api/auth/login`, trình duyệt mới/ẩn danh, đã xoá cookie) vẫn có thể bị người khác khoá tạm 15 phút. Với CLI/CI nên dùng token dài hạn; để khôi phục ngay, khởi động lại tiến trình (bộ đếm nằm trong bộ nhớ, tối đa 10 000 khoá, khoá đang hiệu lực không bị đẩy ra khi đầy).
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

- Mọi request được coi như ADMIN `dev@local`.
- Các method khác `GET`/`HEAD`/`OPTIONS` trên `/api/pentest`, `/api/webscans`, `/api/domains` bị chặn (403). Nghĩa là không tạo domain, crawl, web scan hay pentest được.
- Chỉ dùng cho dev 1 người trên localhost.

## Bắt đổi mật khẩu lần đầu

Tài khoản do `scripts/bootstrap_admin.py` tạo có `must_change_password=True`. Giao diện web hiện hộp đổi mật khẩu bắt buộc. Lưu ý: cờ này chỉ được kiểm tra ở giao diện, API không chặn token của user chưa đổi mật khẩu (xem [[Security and Known Limitations|Security-and-Known-Limitations]]).
