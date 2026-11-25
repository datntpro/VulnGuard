# Bảo mật và hạn chế đã biết

Trang này liệt kê các điểm cần biết khi triển khai, đã đối chiếu với code ở commit `1e0e810` (main, 24/11/2026). Mỗi mục ghi file liên quan để kiểm tra lại khi code thay đổi. Mô hình bảo mật tổng quan xem [[Security and Data Flow|Security-and-Data-Flow]].

## Đã được xử lý (so với bản trước 23/11/2026)

- `run.sh` / `run.ps1` bind `127.0.0.1` mặc định (`VULNGUARD_BIND`) và thêm `.venv/bin` vào `PATH`.
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
| `scripts/setup.py` (gọi từ `setup.sh` khi không có `--no-run`) không thêm `.venv/bin` vào `PATH` (đã bind `127.0.0.1` mặc định theo `VULNGUARD_BIND`; từ chối `AUTH_ENABLED=false` + host không phải loopback) | `scripts/setup.py` | Dùng `bash setup.sh --no-run` rồi `bash run.sh` |
| Unit systemd mẫu dùng `venv/` (không phải `.venv/`); đã đổi sang `--host 127.0.0.1 --workers 1` | `install/vulnguard.service.template`, `install/run.sh` | Sửa đường dẫn venv trước khi cài; muốn mở ra ngoài thì đặt reverse proxy TLS phía trước |
| Quét image local cần `docker-compose.local-images.yml`: container `docker-socket-proxy` vẫn giữ `docker.sock` (chỉ cho GET image/ping/version, POST = 403) | `docker-compose.local-images.yml` | Chỉ bật khi cần; không publish cổng 2375. Mặc định app không mount socket |
| Base image (`python:3.11-slim`) và gói apt (nmap, sqlmap, chromium) chưa pin theo digest/phiên bản | `api/Dockerfile` | Dependabot theo dõi tag; pin digest khi phát hành |
| Docker publish `8080`/`8788` mặc định trên loopback (đã sửa); chỉ SonarQube `9000` (profile `sonar`) vẫn publish trên mọi interface | `docker-compose.yml` | Mở LAN có chủ đích bằng `VULNGUARD_BIND`; đổi `9000` thành `127.0.0.1:9000:9000` hoặc đặt firewall |
| Proxy MITM pentest (Docker 8788) có biến bind riêng `PENTEST_PROXY_BIND` (mặc định loopback), không đi theo `VULNGUARD_BIND` | `docker-compose.yml` | Chỉ mở nếu cần dùng proxy từ máy khác |
| CSP nền cho phép `'unsafe-inline'` script | `api/main.py` | Hạn chế rò rỉ/nhúng khung nhưng không chặn XSS inline; CSP nghiêm ngặt cần refactor `onclick` inline (đã hoãn) |
| SCM `base_url`: chỉ kiểm tra IP lúc dùng, chưa pin IP | `scanner/scm/providers.py` | DNS rebinding hẹp nhưng chưa loại trừ; dải private mặc định cho phép (`SCM_ALLOW_PRIVATE_HOSTS=false` để cấm) |

### Chỉ 1 worker / 1 instance

VulnGuard giữ trạng thái trong bộ nhớ tiến trình: khoá scan đang chạy, registry proxy pentest, scheduler,
bộ đếm khoá đăng nhập (lockout), nonce xác nhận của Co-work. Chạy nhiều worker hoặc nhiều instance trỏ vào cùng
DB sẽ làm các cơ chế này sai lệch (lockout bị vòng qua, scan chạy trùng, proxy "không tìm thấy").
`run.sh`/`install/run.sh`/unit systemd ép `--workers 1` và `VULNGUARD_WORKERS>1` bị bỏ qua kèm cảnh báo.
Không đặt nhiều instance sau load balancer.

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

## Coworker Host (Co-work) — mô hình đe dọa

Token `VULNGUARD_COWORKER_TOKEN` nằm trong env của container API; mã chạy với quyền `appuser` trong
container đọc được nó (`/proc/1/environ`). Vì vậy **chính sách phía host** mới là lớp kiểm soát thật:

- `COWORKER_EXEC_MODE=safe` (mặc định): chỉ lệnh đọc; không có đường xác nhận. `trusted`: lệnh ngoài
  whitelist cần `confirm_id` do server cấp (dùng một lần, 120 giây, gắn với đúng lệnh). `off`: tắt exec.
- Đối số luôn bị giới hạn trong folder root (symlink được resolve); `find -exec`, `grep -R`, `git -c ...` bị chặn.
- Tiến trình con chạy với môi trường tối thiểu (không có token). Scanner phía API cũng gỡ các secret khỏi env.
- Folder nhạy cảm (`~/.ssh`, `~/Library`, `/etc`, tổ tiên của home, thư mục dữ liệu coworker) không cấp quyền được;
  nên đặt thêm `COWORKER_ALLOWED_ROOTS`. Ghi vào `.git`, `.husky`, `.vscode`, `.idea`, `.direnv`, `.envrc` bị chặn.

Rủi ro còn lại: đọc token cùng uid trong container; ở chế độ `trusted` người giữ token chạy được mã
(interpreter thoát được giới hạn đối số theo thiết kế); file code được ghi sẽ chạy khi nhà phát triển chạy nó.

Rủi ro còn lại (Coworker, bổ sung): hardlink có sẵn trong folder trỏ tới file ngoài root (không tạo được bằng lệnh safe);
chế độ `trusted` = người giữ token chạy được mã.
Safe-mode git từ chối repo có toplevel/git-dir ngoài root hoặc `.git/info/attributes` không rỗng. Repo có `.git` do kẻ tấn công cung cấp
vẫn là lớp rủi ro cần thận trọng: chỉ cấp quyền cho dự án đáng tin.
