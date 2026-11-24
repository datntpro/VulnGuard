# Bảo mật và hạn chế đã biết

Trang này liệt kê các điểm cần biết khi triển khai, đã đối chiếu với code ở commit `1e0e810` (main, 24/11/2026). Mỗi mục ghi file liên quan để kiểm tra lại khi code thay đổi. Mô hình bảo mật tổng quan xem [[Security and Data Flow|Security-and-Data-Flow]].

## Đã được xử lý (so với bản trước 23/11/2026)

- `run.sh` / `run.ps1` bind `127.0.0.1` mặc định (`VULNGUARD_HOST`) và thêm `.venv/bin` vào `PATH`.
- `scripts/bootstrap_admin.py` không in mật khẩu ra console, đặt `must_change_password=True`.
- MCP HTTP bắt buộc `VULNGUARD_MCP_TOKEN` (fail-closed), bind `127.0.0.1` mặc định.
- Crawl và web scan bắt buộc xác minh quyền sở hữu domain.
- Web scan: `fuzz` chỉ ADMIN, có `exclude_tags`, rate mặc định 10, có export.
- Orchestrator báo tool `skipped` thay vì im lặng; báo cáo HTML liệt kê mọi tool kèm trạng thái.
- Pentest: chỉ ADMIN uỷ quyền engagement; không tự duyệt; duyệt bắt buộc ghi chú; khoá scope khi đã uỷ quyền; kiểm DNS trước mỗi tool; redact output.
- Auth tắt thì khoá các tính năng quét chủ động.

## Binding mạng và triển khai

| Vấn đề | Nơi | Khuyến nghị |
|---|---|---|
| `scripts/setup.py` (gọi từ `setup.sh` khi không có `--no-run`) chạy uvicorn trên `0.0.0.0` và không thêm `.venv/bin` vào `PATH` | `scripts/setup.py` | Dùng `bash setup.sh --no-run` rồi `bash run.sh` |
| `run_demo.sh` bind `0.0.0.0` | `run_demo.sh` | Chỉ chạy demo trên máy cá nhân / mạng tin cậy |
| Unit systemd mẫu bind `0.0.0.0` và dùng `venv/` (không phải `.venv/`) | `install/vulnguard.service.template`, `install/run.sh` | Sửa `--host` và đường dẫn venv trước khi cài |
| Docker publish `8080`, `8788` (và `9000` của SonarQube) trên mọi interface của host | `docker-compose.yml` | Đổi thành `127.0.0.1:8080:8080` hoặc đặt firewall/reverse proxy |
| Container mount `/var/run/docker.sock` và chạy root (Dockerfile không có `USER`) | `docker-compose.yml`, `api/Dockerfile` | Bỏ mount nếu không quét image; coi container như có quyền root trên host |
| Proxy MITM pentest `bind_host` mặc định `0.0.0.0` | `api/routes/pentest.py` | Truyền `bind_host: "127.0.0.1"` khi start |
| CORS `allow_origins=["*"]` (không kèm credentials) | `api/main.py` | Cookie vẫn an toàn nhờ `SameSite=Strict`; token Bearer thì cẩn thận |
| `/docs`, `/openapi.json` công khai | `api/main.py` | Chặn ở reverse proxy nếu không muốn lộ danh sách endpoint |

## Xác thực và phân quyền

- `must_change_password` chỉ được ép ở giao diện web; API vẫn chấp nhận token của user chưa đổi mật khẩu.
- Không có rate limit / khoá tài khoản khi đăng nhập sai nhiều lần.
- `POST /api/auth/setup` công khai khi DB chưa có user: instance mới chưa bootstrap admin mà mở ra mạng thì ai vào trước người đó thành ADMIN.
- Quy tắc ADMIN_ONLY dùng `PUT /api/settings`, nên các endpoint `POST`/`DELETE` trong settings **không** giới hạn ADMIN: `POST/DELETE /api/settings/report-branding/logo`, `POST /api/settings/sonarqube/test`, `POST /api/settings/smtp/test`.
- `/api/scm/*` không giới hạn ADMIN: mọi ANALYST thêm/xoá kết nối SCM và token.
- `/api/assets` PATCH/DELETE không giới hạn ADMIN.
- Duyệt hành động pentest: mọi ANALYST/ADMIN khác người khởi chạy đều duyệt được (không bắt buộc ADMIN).
- `mask_secret` hiển thị 7 ký tự đầu và 4 ký tự cuối của secret dài hơn 12 ký tự.

## Quét code

- **Trivy IaC luôn bị `skipped`**: scanner khai báo `tool_name = "trivy-iac"`, orchestrator kiểm `which trivy-iac` nên không tìm thấy dù đã cài `trivy`. Checkov vẫn chạy cho IaC.
- Trivy SCA và Trivy container dùng chung key tiến độ `trivy`.
- Gitleaks ghi report vào đường dẫn cố định `/tmp/gitleaks-report.json`; 2 scan chạy song song có thể ghi đè nhau.
- Bandit chạy với `-ll` (chỉ MEDIUM trở lên), trong khi comment trong code ghi LOW.
- `approve-check` không tính tool bị `skipped`: thiếu tool vẫn có thể "pass".
- Kiểm tra tool của `scripts/setup.py` chỉ dùng `PATH` hiện tại, không thấy tool cài trong `.venv/bin` nếu venv chưa kích hoạt.
- CLI không gửi token nên nhận `401` khi `AUTH_ENABLED=true`.

## Domain và web scan

- Thiếu `dnspython` trong `api/requirements.txt`: cách xác minh DNS TXT có thể luôn thất bại; dùng file `.well-known/vulnguard.txt`.
- Katana không có rate limit và dùng `-aff` (tự điền và gửi form) nên crawl có thể tạo dữ liệu trên site đích.
- `exclude_tags` của web scan mặc định rỗng: muốn tránh template DoS/fuzz/intrusive phải tự truyền.
- Docstring `nuclei_runner` vẫn ghi rate 50; giá trị mặc định thật của web scan là 10 (tool `web_vuln_scan` của Pentest Agent vẫn mặc định 50).

## Pentest Agent

- Engagement pentest **không** yêu cầu xác minh quyền sở hữu domain (khác web scan). README ghi ngược lại, code không làm vậy.
- Replay traffic chỉ kiểm host nằm trong scope của **bất kỳ** engagement nào, kể cả chưa uỷ quyền hoặc đã hết hạn.
- Kiểm tra DNS trước khi chạy tool nằm trong khối `try/except: pass`: nếu bước kiểm tra ném exception (khác với kết quả "ngoài scope"), tool vẫn chạy.
- Pentest Agent cần Anthropic (API/WIF) hoặc Bedrock kể cả khi AI mode (Settings → AI Provider) là `local_only`; dữ liệu target đi ra nhà cung cấp AI. `docs/DATA_FLOW.md` nói có thể dùng Ollama là không đúng với code.
- Proxy MITM không hỗ trợ HTTP/2, WebSocket.

## Lưu trữ và repo

- `.gitignore` chỉ bỏ qua `.env`, `storage/admin_credentials.txt`, `storage/scanner_config.json`, `storage/pentest_ca/`, DB, report... **Không** có `storage/secret.key`, `storage/ai_config.json`, `storage/runtime_settings.json`, `storage/intel/`, `storage/report_branding.json` và thư mục logo. Đừng commit thư mục `storage/`.
- Thư mục `.coworker_venv/` (1263 file) đang được commit trong repo.
- `install/run.sh` dùng `venv/` còn `setup.sh` dùng `.venv/`.

## Báo lỗi bảo mật

Báo riêng cho maintainer (`datntpro`), không mở issue công khai với chi tiết khai thác.
