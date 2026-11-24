# Cấu hình

Cấu hình đến từ 3 nơi:

1. **Biến môi trường / `.env`**: đọc bởi `api/config.py` (pydantic-settings, tên biến viết hoa) và các script chạy (`run.sh`, `docker-compose.yml`).
2. **File JSON trong `storage/`**: chỉnh qua giao diện Settings, sống qua restart.
3. **Database SQLite**: user, project, scan, domain, engagement, SCM, connector...

Mẫu: `.env.example` (Docker) và `.env.native.example` (Native). Không commit `.env` lên git.

## Biến môi trường của ứng dụng (`api/config.py`)

| Biến | Mặc định trong code | Ý nghĩa |
|---|---|---|
| `DATABASE_URL` | `sqlite:////app/storage/db/vulnguard.db` (`run.sh` đặt lại thành `storage/db/vulnguard.db` trong thư mục cài) | DB SQLite. Thư mục `storage/` được suy ra từ đường dẫn này |
| `AUTH_ENABLED` | `true` | Bật đăng nhập. `false` chỉ cho dev 1 người, và khi tắt thì các API quét chủ động bị khoá |
| `VULNGUARD_SECRET_KEY` | rỗng | Khoá ký JWT và mã hoá Fernet. Rỗng thì tự sinh `storage/secret.key`. Đặt cố định nếu chạy nhiều instance |
| `SESSION_TTL_HOURS` | `12` | Thời hạn phiên |
| `COOKIE_SECURE` | `false` | Bật khi chạy sau HTTPS reverse proxy |
| `APP_ENV` | `production` | Ảnh hưởng scheduler (xem `VULNGUARD_SCHEDULER`) |
| `DEPLOY_MODE` | `docker` (`run.sh` đặt `native`) | UI dùng để gợi ý đường dẫn scan đúng |
| `OLLAMA_URL` | `http://host.docker.internal:11434` | Endpoint Ollama. Bản native nên đặt `http://localhost:11434` |
| `OLLAMA_MODEL` | `llama3.2` | Model text |
| `OLLAMA_TIMEOUT` | `120` | Giây |
| `OLLAMA_VISION_MODEL` | `llama3.2-vision` | Model đọc ảnh trong tài liệu (Document Review) |
| `DOC_MAX_IMAGES` | `10` | Số ảnh tối đa mỗi tài liệu |
| `COWORKER_URL` | `http://host.docker.internal:8765` | Coworker Host Service |
| `COWORKER_TIMEOUT` | `30` | Giây |
| `MAX_SCANS_PER_PROJECT` | `5` | Số scan giữ lại mỗi project (scan cũ nhất bị xoá khi vượt) |
| `MAX_CRAWLS_PER_DOMAIN` | `5` | Số crawl giữ lại mỗi domain |
| `MAX_WEBSCANS_PER_DOMAIN` | `5` | Số web scan giữ lại mỗi domain |
| `NUCLEI_TIMEOUT_MINUTES` | `60` | Timeout mỗi web scan |
| `BLOCK_SEVERITY_THRESHOLD` | `HIGH` | Ngưỡng chặn approve (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `SONARQUBE_URL`, `SONARQUBE_TOKEN` | rỗng | SonarQube. Có thể ghi đè trong Settings |
| `SONARQUBE_TIMEOUT` | `900` | Giây |
| `FEATURE_COWORKER`, `FEATURE_DOCREVIEW`, `FEATURE_FILE_ASSISTANT` | `true` | Tắt module. API của module bị tắt trả 404 |

## Biến dùng bởi script và module khác

| Biến | Nơi dùng | Ý nghĩa |
|---|---|---|
| `VULNGUARD_HOST` | `run.sh`, `run.ps1`, `install/run.sh` | Địa chỉ bind, mặc định `127.0.0.1`. Đặt `0.0.0.0` để mở ra ngoài (script in cảnh báo) |
| `VULNGUARD_PORT` | các script, compose | Cổng, mặc định `8080` |
| `VULNGUARD_WORKERS` | `run.sh` | Số worker uvicorn, mặc định `1` |
| `VULNGUARD_VENV` | `run.sh` | Thư mục venv, mặc định `.venv` |
| `AI_CONFIG_FILE` | `api/services/ai_config.py` | Mặc định `storage/ai_config.json` |
| `SCANNER_CONFIG_FILE` | orchestrator, settings | Bật/tắt từng tool. Mặc định trong code `/app/storage/scanner_config.json`; `run.sh` đặt về `storage/scanner_config.json` |
| `RUNTIME_SETTINGS_FILE` | `api/services/runtime_settings.py` | Mặc định `storage/runtime_settings.json` (Ollama endpoint/model, SonarQube, SMTP) |
| `VULNGUARD_SCHEDULER` | `api/services/scheduler.py` | `1/true/on` hoặc `0/false/off`. Không đặt thì bật khi `APP_ENV=production` |
| `VULNGUARD_MCP_TOKEN` | `mcp_server/server.py` | Bắt buộc khi chạy MCP ở chế độ HTTP |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | `scripts/bootstrap_admin.py` | Email / mật khẩu ADMIN đầu tiên |
| `SCAN_WORKSPACE` | compose | Thư mục host mount vào `/workspace` |
| `DOCKER_SOCK` | compose | Đường dẫn Docker socket mount vào container |
| `PENTEST_PROXY_PORT` | compose | Cổng host publish cho MITM proxy (mặc định `8788`) |
| `SEMGREP_HOME` | Dockerfile, `install/run.sh` | Cache rule Semgrep |
| `COWORKER_HOST_PORT`, `COWORKER_DATA_DIR` | `coworker_host/run.sh` | Cổng (mặc định `8765`) và thư mục dữ liệu của Coworker Host |
| `VULNGUARD_DEMO` | `run_demo.sh` | Bỏ qua bước dọn scan/run treo khi khởi động |

## Cổng và binding

| Thành phần | Cổng mặc định | Bind mặc định |
|---|---|---|
| Web UI + API | `8080` | `127.0.0.1` khi dùng `run.sh`; `0.0.0.0` khi `setup.py` tự chạy, `run_demo.sh`, systemd template, và trong container Docker |
| Recording MITM proxy (Pentest) | `8788` | `0.0.0.0` (giá trị mặc định của `bind_host` trong `POST /api/pentest/engagements/{id}/proxy/start`) |
| MCP server HTTP | `8899` | `127.0.0.1` (`--host`) |
| Coworker Host | `8765` | `127.0.0.1` |
| SonarQube (profile `sonar`) | `9000` | compose publish |

## AI provider (Settings → AI Provider, chỉ ADMIN)

Lưu trong `storage/ai_config.json` (ghi với quyền 600). API key được mã hoá Fernet, API chỉ trả `api_key_set` và `api_key_hint`, không bao giờ trả nguyên văn.

| `mode` | Hành vi |
|---|---|
| `local_only` (mặc định) | Chỉ Ollama. Dữ liệu quét không rời máy |
| `hybrid` | Ollama chấm trước. Finding có severity ≥ `hybrid.escalate_min_severity` (mặc định `HIGH`) hoặc có FP% nằm trong `[fp_band_low, fp_band_high]` (mặc định 15 đến 85) thì gửi cloud xác minh |
| `cloud_only` | Mọi finding dùng cloud provider |

| `provider` | Xác thực | Model mặc định trong code |
|---|---|---|
| `anthropic` | `auth_mode`: `api_key`, `wif` (Workload Identity Federation: `federation_rule_id`, `organization_id`, `identity_token_file`), `environment` (SDK tự lấy từ môi trường máy chủ) | `claude-opus-5-5` |
| `bedrock` | `auth_mode`: `aws_chain`, `profile` (`aws sso login` / `kiro-cli login`), `bedrock_api_key`; `region` mặc định `us-east-1` | `anthropic.claude-opus-5-5` |
| `openai` | API key, `base_url` tuỳ chọn | `gpt-4o` |
| `openrouter` | API key, base `https://openrouter.ai/api/v1` | `anthropic/claude-3.5-sonnet` |

Tuỳ chọn quyền riêng tư (`privacy`): `send_code_context` (mặc định bật), `context_lines` (mặc định 15, tối đa 80), `redact_secrets` (mặc định bật). Trước khi gửi cloud, `scanner/cloud_ai.py` che secret (private key, AWS key, `sk-...`, token GitHub/Slack, JWT, dạng `password=...`) và PII Việt Nam (CCCD/CMND, số điện thoại, email, IP nội bộ). Xem `docs/DATA_FLOW.md`.

> **Pentest Agent luôn cần Claude** qua provider `anthropic` hoặc `bedrock`, bất kể `mode`. Provider `openai`/`openrouter` làm run thất bại với thông báo rõ ràng. Pentest Agent không dùng Ollama.

API liên quan: `GET/PUT /api/ai/config`, `POST /api/ai/test`, `POST /api/vulns/{id}/reanalyze`.

## Ollama (Settings → Ollama)

Endpoint và model có thể đổi lúc chạy, lưu ở `storage/runtime_settings.json`. API: `GET/PUT /api/ollama/endpoint`, `GET /api/ollama/health`, `GET /api/ollama/models`, `POST /api/ollama/pull`, `DELETE /api/ollama/models/{name}`, `PUT /api/ollama/active-model`, `GET/PUT /api/ollama/vision-model`.

## Bật/tắt từng scanner (Settings → Scanner Tools)

`GET /api/settings/scanners` trả trạng thái cài đặt + phiên bản của từng tool. `PUT /api/settings/scanners` với body `{"enabled_tools": {"semgrep": false}}` để tắt. Tool bị tắt không chạy và không xuất hiện trong tiến trình scan.

## SonarQube (Settings → Scanner Tools → SonarQube)

Nhập URL + token (token mã hoá, chỉ hiện hint), lưu ở `storage/runtime_settings.json` và ghi đè `SONARQUBE_URL`/`SONARQUBE_TOKEN`. Dùng server sẵn có hoặc bundled (`docker compose --profile sonar up -d`). `POST /api/settings/sonarqube/test` kiểm tra `/api/system/status`, token (`/api/authentication/validate`) và có binary `sonar-scanner` hay không. Scanner SonarQube chỉ chạy khi có đủ URL, token và `sonar-scanner` trong `PATH`.

## SMTP (trang Nguồn mã (SCM) → SMTP)

`GET/PUT /api/settings/smtp` với `host`, `port`, `username`, `password` (write-only, mã hoá), `from_addr`, `use_tls`. `POST /api/settings/smtp/test` với `{"to": "..."}` để gửi thử. Dùng để gửi báo cáo PDF cho owner sau scan SCM theo lịch (xem [[SCM Integration|SCM-Integration]]).

## Branding báo cáo PDF (Settings → Báo cáo)

`PUT /api/settings/report-branding` với `org_name`, `org_tagline`, `report_title`, `footer_text`, `confidential_label`. Upload logo PNG/JPG tối đa 2 MB qua `POST /api/settings/report-branding/logo`.

## File quan trọng trong `storage/`

| File | Nội dung |
|---|---|
| `db/vulnguard.db` | Database |
| `secret.key` | Khoá ký JWT + mã hoá secret (khi không đặt `VULNGUARD_SECRET_KEY`). Mất file này thì mọi secret đã mã hoá không giải mã được. Sao lưu cùng DB |
| `ai_config.json` | Cấu hình AI (key đã mã hoá) |
| `runtime_settings.json` | Ollama, SonarQube, SMTP (secret đã mã hoá) |
| `scanner_config.json` | Bật/tắt tool |
| `pentest_ca/` | CA của MITM proxy (key chmod 600) |
| `intel/` | Cache EPSS / CISA KEV |
| `admin_credentials.txt` | Mật khẩu ADMIN ban đầu. Xoá sau khi đổi mật khẩu |

> **Lưu ý `.gitignore`:** trong các file trên, `.gitignore` hiện chỉ liệt kê `storage/admin_credentials.txt`, `storage/scanner_config.json`, `storage/pentest_ca/`, `storage/db/*.db`, `storage/documents/`, `storage/demo/`. Các file `storage/secret.key`, `storage/ai_config.json`, `storage/runtime_settings.json`, thư mục `storage/intel/` và logo branding **không** bị ignore. Không commit thư mục `storage/`.
