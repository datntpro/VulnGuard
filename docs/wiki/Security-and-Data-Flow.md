# Security & Data Flow

## Mô hình bảo mật
- **Auth**: JWT trong cookie HttpOnly; **RBAC** ADMIN / ANALYST / VIEWER. Mật khẩu hash scrypt.
- **Mặc định localhost** (`127.0.0.1`) khi chạy bằng `run.sh` / `run.ps1` / `install/run.sh`; mở LAN phải chủ động đặt `VULNGUARD_BIND=0.0.0.0` (Docker và native dùng chung biến; xem [[LAN Access|LAN-Access]]). App từ chối khởi động nếu bind LAN mà `AUTH_ENABLED=false`.
- **Secret mã hoá tại chỗ** (Fernet): API key cloud AI, token connector/SonarQube, mật khẩu SMTP; chỉ hiện hint, không trả raw.
- **Mật khẩu ADMIN** không in ra màn hình/log; lưu file `storage/admin_credentials.txt` (chmod 600); **bắt đổi lần đăng nhập đầu**.
- Quét chủ động (web/crawl/pentest) **bị khoá khi `AUTH_ENABLED=false`**.
- **Xác minh quyền sở hữu domain** (DNS TXT `vulnguard-verify=<token>` hoặc file `/.well-known/vulnguard.txt`) bắt buộc trước crawl/web scan. Pentest Agent **không** dùng cơ chế này: nó dựa vào scope do ADMIN uỷ quyền.
- **Tách quyền** pentest: chỉ ADMIN uỷ quyền engagement; người khởi chạy run không tự duyệt hành động của mình; duyệt phải ghi lý do; không đổi được **scope** khi engagement đang ở trạng thái đã uỷ quyền.
- **Scope gate** phân giải DNS, chặn IP nội bộ/loopback/metadata (`169.254.169.254`) trừ khi scope ghi rõ IP/CIDR, chống SSRF/DNS rebinding.
- **MCP HTTP** bắt buộc bearer token (fail-closed).

## Dữ liệu nào ở lại máy / dữ liệu nào rời máy
**Luôn ở lại máy (local-only)**: mã nguồn quét, kết quả/lỗ hổng/triage/báo cáo (SQLite), secret đã cấu hình (mã hoá), phân tích AI bằng Ollama.

**Chỉ rời máy khi BẬT (opt-in)**:
| Tính năng | Gửi gì | Tới đâu | Tắt bằng |
|---|---|---|---|
| AI đám mây (hybrid/cloud) | Finding + ngữ cảnh code (đã redact secret + PII) | Provider bạn chọn | `mode=local_only` |
| Pentest Agent | Goal, scope, target và output tool (output đã redact) | Anthropic API hoặc Bedrock | Không chạy Pentest Agent (agent không hỗ trợ Ollama) |
| Threat intel | Chỉ tải feed công khai về | FIRST/CISA | Dùng cache offline |
| Connector XDR/NAC | Truy vấn hệ thống bạn khai báo | Server bạn nhập | Không thêm connector |
| SCM (GitHub/GitLab) | Token để gọi API và `git clone` | GitHub/GitLab bạn khai báo | Không thêm kết nối SCM |
| Semgrep registry rules | Tải ruleset `p/...` khi có internet (chạy với `--metrics=off`) | semgrep.dev | Chạy offline (chỉ bundled rules) |
| Gửi báo cáo SMTP | Báo cáo PDF + tóm tắt | Mail server bạn cấu hình | Không bật lịch/email |

**Redaction trước khi gửi cloud**: private key, AWS key, `sk-…`, GitHub/Slack token, JWT, gán `password=…`; PII tiếng Việt: CCCD/CMND, SĐT VN, email, IP nội bộ. Redaction là lớp phòng vệ, không tuyệt đối; dữ liệu nhạy cảm cao nên giữ `local_only`.


Nguồn: `docs/DATA_FLOW.md` trong repo. Lưu ý: dòng Pentest Agent trong `docs/DATA_FLOW.md` ghi có thể dùng Ollama, nhưng `scanner/pentest/agent.py` chỉ chạy với provider Anthropic/Bedrock.
