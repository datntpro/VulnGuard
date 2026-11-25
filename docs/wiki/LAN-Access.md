# Truy cập từ máy khác trong LAN

**Mặc định VulnGuard chỉ nghe `127.0.0.1`** (Docker: cổng publish chỉ trên loopback). Máy khác trong LAN sẽ nhận
*connection refused*. Đây là mặc định bảo mật có chủ đích. Một biến duy nhất điều khiển việc này cho **cả Docker lẫn native**:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `VULNGUARD_BIND` | `127.0.0.1` | Địa chỉ bind của UI/API. `0.0.0.0` = mở cho mọi máy trong mạng. (`VULNGUARD_HOST` là alias **deprecated**.) |
| `ALLOWED_HOSTS` | rỗng | Hostname/IP người dùng LAN gõ vào trình duyệt, csv. Vd `192.168.1.63,vulnguard.lan` |
| `COOKIE_SECURE` | `false` | `true` **chỉ khi** truy cập qua HTTPS (reverse proxy) |
| `PENTEST_PROXY_BIND` | `127.0.0.1` | Bind riêng của proxy MITM Pentest (Docker, cổng 8788). Giữ loopback dù UI mở LAN |

## 1. Điều kiện tiên quyết (đọc trước khi mở)

- **Giữ `AUTH_ENABLED=true`.** App **từ chối khởi động** nếu bind không phải loopback mà `AUTH_ENABLED=false` (cả `run.sh`,
  `run.ps1`, `install/run.sh`, `scripts/setup.py` lẫn chính app). Khi auth tắt, Host cũng luôn bị giới hạn loopback.
- **Tạo tài khoản ADMIN trước khi mở LAN.** Khi chưa có user, `POST /api/auth/setup` là đường chiếm quyền ADMIN. Phiên bản có
  *setup token* (PR-G, `VULNGUARD_SETUP_TOKEN` / `storage/setup_token`) chặn việc này; vẫn nên tạo admin khi còn ở localhost.
- Firewall chỉ cho mạng tin cậy. Proxy MITM (8788) và `coworker_host` (8765) **không** nên mở ra LAN.

## 2. Docker

```bash
# Cách 1: biến môi trường (hoặc ghi vào .env cạnh docker-compose.yml)
VULNGUARD_BIND=0.0.0.0 ALLOWED_HOSTS=192.168.1.63 docker compose up -d
docker compose ps        # PORTS: 0.0.0.0:8080->8080  và  127.0.0.1:8788->8788

# Cách 2: file override (chỉ mở 8080, proxy luôn loopback; cần Compose ≥ 2.24)
docker compose -f docker-compose.yml -f docker-compose.lan.yml up -d
```

Compose truyền `AUTH_ENABLED`, `ALLOWED_HOSTS`, `COOKIE_SECURE`, `CORS_ALLOW_ORIGINS`, `VULNGUARD_SECRET_KEY`,
`SESSION_TTL_HOURS`, `EXPOSE_API_DOCS`, `SCM_ALLOW_HTTP`, `SCM_ALLOW_PRIVATE_HOSTS` từ `.env` vào container
(trước đây container không đọc `.env` nên các giá trị này không có tác dụng).

## 3. Native

```bash
VULNGUARD_BIND=0.0.0.0 ALLOWED_HOSTS=192.168.1.63 bash run.sh      # Windows: $env:VULNGUARD_BIND="0.0.0.0"; .\run.ps1
# hoặc ghi vào .env (run.sh tự đọc)
```
`run.sh` in cảnh báo và gợi ý khi bind ra ngoài. Địa chỉ IP của máy: macOS `ipconfig getifaddr en0`, Linux `hostname -I`.
Unit systemd mẫu bind `127.0.0.1` (đặt reverse proxy phía trước, hoặc sửa `--host`).

## 4. Khuyến nghị: TLS qua reverse proxy (Caddy)

HTTP thuần trong LAN lộ cookie phiên và mật khẩu cho người nghe mạng. Cách tốt hơn: app **vẫn bind loopback**, chỉ proxy mở 443.

```caddyfile
vulnguard.lan {
    tls internal
    reverse_proxy 127.0.0.1:8080
}
```
Rồi đặt: `ALLOWED_HOSTS=vulnguard.lan`, `COOKIE_SECURE=true`, chạy uvicorn với
`--proxy-headers --forwarded-allow-ips=127.0.0.1` nếu cần. Import CA nội bộ của Caddy vào máy khách.
(`COOKIE_SECURE=true` trên HTTP thuần sẽ gây vòng lặp đăng nhập → 401.)

## 5. Chẩn đoán

| Triệu chứng (từ máy khác) | Nguyên nhân | Cách xử lý |
|---|---|---|
| `curl: (7) Failed to connect` | Vẫn bind `127.0.0.1` hoặc firewall | Đặt `VULNGUARD_BIND=0.0.0.0`; mở firewall (macOS: cho phép `python3`/`uvicorn`; Linux `ufw allow 8080`; Windows: rule inbound) |
| `421 {"code":"bad_host"}` | `ALLOWED_HOSTS` đã đặt nhưng thiếu IP/hostname này; hoặc `AUTH_ENABLED=false` | Thêm vào `ALLOWED_HOSTS`; bật auth |
| `403 {"code":"bad_origin"}` | Request ghi từ origin khác Host (vd qua proxy đổi Host) | Proxy phải giữ nguyên `Host`; hoặc đặt `CORS_ALLOW_ORIGINS` |
| Đăng nhập xong vẫn `401` | `COOKIE_SECURE=true` nhưng truy cập qua HTTP | Dùng HTTPS hoặc `COOKIE_SECURE=false` |
| App không khởi động: "AUTH_ENABLED=false không được phép…" | Bind LAN + auth tắt | Bật auth hoặc bind loopback |

Kiểm tra nhanh: `curl -s http://<IP-LAN>:8080/api/auth/status`.
