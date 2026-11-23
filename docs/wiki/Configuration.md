# Configuration

Cấu hình qua **biến môi trường** (file `.env` ở gốc repo) và **UI Settings**. Secret (API key, token, mật khẩu SMTP) được **mã hoá Fernet** khi lưu, chỉ hiện hint.

## Biến môi trường chính
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `VULNGUARD_PORT` | 8080 | Cổng HTTP |
| `VULNGUARD_HOST` | 127.0.0.1 | Địa chỉ bind (đặt `0.0.0.0` để mở LAN) |
| `AUTH_ENABLED` | true | Bật auth (production luôn bật; false khoá web scan/crawl/pentest) |
| `DATABASE_URL` | sqlite:///…/storage/db/vulnguard.db | DB |
| `APP_ENV` | production | Môi trường |
| `VULNGUARD_SCHEDULER` | (auto) | Bật/tắt scheduler quét theo lịch (mặc định bật khi production) |
| `BLOCK_SEVERITY_THRESHOLD` | HIGH | Ngưỡng chặn approve deploy |
| `VULNGUARD_MCP_TOKEN` | — | **Bắt buộc** khi chạy MCP server ở chế độ HTTP |
| `FEATURE_COWORKER` / `FEATURE_DOCREVIEW` / `FEATURE_FILE_ASSISTANT` | true | Feature flag ẩn module khỏi bản bán |

## AI Provider (Settings → AI Provider)
Chế độ: `local_only` (mặc định, chỉ Ollama) · `hybrid` (Ollama trước, cloud xác minh) · `cloud_only`.
Cloud provider hỗ trợ:
- **Anthropic Claude API** (API key / Workload Identity Federation / environment).
- **Amazon Bedrock** — AWS chain / profile (tạo bởi `kiro-cli login` hoặc `aws sso login`) / Bedrock API key (headless).
- **OpenAI (ChatGPT)** — API key, base URL tùy chọn.
- **OpenRouter** — 1 key, nhiều model.

Khi gửi cloud, secret và **PII tiếng Việt** (CCCD/SĐT/email/IP nội bộ) được redact trước.

## Ollama (Settings → Ollama)
Không bắt buộc Docker. Cài native (`ollama serve` → `http://localhost:11434`) hoặc trỏ IP máy khác (`http://192.168.1.50:11434`). Endpoint + model lưu bền vững qua restart.

## SonarQube (Settings → Scanner Tools → SonarQube)
Nhập **URL + token** (mã hoá). Dùng server sẵn có hoặc bundled (`docker compose --profile sonar up -d`). Nút **Kiểm tra kết nối** xác nhận server + token + binary sonar-scanner.

## Báo cáo (Settings → Báo cáo)
Tùy chỉnh **logo, tên tổ chức, tiêu đề, footer, nhãn bảo mật** trên PDF báo cáo.

## SMTP (trang Nguồn mã → SMTP)
Cấu hình host/port/user/password/from để **gửi báo cáo PDF tự động** cho owner sau mỗi lần quét theo lịch.

## Runtime files (KHÔNG commit)
`storage/secret.key`, `storage/admin_credentials.txt`, `storage/ai_config.json`, `storage/runtime_settings.json` — chứa secret/khóa, đã được `.gitignore`.
