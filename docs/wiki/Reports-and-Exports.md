# Báo cáo và export

## Code scan

Scan phải ở trạng thái `COMPLETED`, nếu không API trả 400.

### Export: `GET /api/scans/{scan_id}/export`

| `format` | Nội dung | File |
|---|---|---|
| `json` (mặc định) | Thông tin scan + toàn bộ finding (kèm triage, waiver, AI) | `vulnguard_<project>_<n>.json` |
| `csv` | Bảng finding | `.csv` |
| `pdf` | Báo cáo doanh nghiệp (bìa, bảng, header/footer, số trang), font DejaVu nên hiển thị tiếng Việt; có mục ánh xạ tuân thủ | `.pdf` |
| `md` | Markdown | `.md` |
| `sarif` | SARIF 2.1.0 cho GitHub Code Scanning / GitLab / Azure DevOps | `.sarif` |
| `ai` | JSON tối giản cho LLM (mô tả cắt 800 ký tự), mở inline trên trình duyệt | `.ai.json` |

Tham số lọc:

| Tham số | Giá trị |
|---|---|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `status` | Trạng thái triage (xem [[Scanning and Triage|Scanning-and-Triage]]) |
| `scan_type` | `SAST`, `SCA`, `CONTAINER`, `IAC`, `SECRETS` |
| `diff` | `all` (mặc định), `new` (lần đầu xuất hiện ở scan này), `recurrent` (đã có từ scan trước) |
| `scope` | `all` (mặc định), `active` (chỉ `OPEN`, `CONFIRMED`, `URGENT`, `PROPOSED_NE`) |

Giá trị lọc sai trả 400. PDF ghi chú phạm vi nếu dùng `diff`/`scope`.

### Báo cáo HTML: `GET /api/scans/{scan_id}/report?download=false`

Báo cáo tiếng Việt: gộp trùng finding từ nhiều tool, nhóm theo package (SCA) / rule (SAST) / loại secret / IaC check, kèm giải thích và gợi ý sửa của AI, và danh sách mọi tool với trạng thái (`done`, `error`, `skipped`). `download=true` để tải file `.html`.

### Branding

Settings → Báo cáo: `org_name`, `org_tagline`, `report_title`, `footer_text`, `confidential_label` và logo. Lưu ở `storage/report_branding.json` (ghi đè đường dẫn bằng `REPORT_BRANDING_FILE`). API: `GET/PUT /api/settings/report-branding`, `POST/DELETE /api/settings/report-branding/logo`, `GET /api/settings/report-branding/logo-image`.

### Email

Scan theo lịch SCM có thể gửi PDF cho owner qua SMTP. Xem [[SCM Integration|SCM-Integration]].

## Web scan

`GET /api/webscans/{scan_id}/export?format=json|csv|html`. Bản HTML in ra PDF bằng trình duyệt.

## Crawl

`GET /api/domains/crawls/{crawl_id}/export?format=`:

| `format` | Nội dung |
|---|---|
| `json` | Danh sách endpoint |
| `sitemap_xml` | sitemap.xml |
| `waf_baseline` | Baseline positive security theo path: method, query/body param đã thấy, content-type |
| `modsecurity` | Snippet rule ModSecurity mẫu sinh từ baseline (cần review trước khi dùng) |

## Document Review

`GET /api/docreview/versions/{version_id}/export?download=false`: báo cáo HTML cho một phiên bản tài liệu; `download=true` để tải file.

## Pentest

Không có endpoint export riêng. Dữ liệu run, finding và traffic lấy qua các API `GET /api/pentest/...` (xem [[API Reference|API-Reference]]).

## Xuất báo cáo PDF: engine Typst (đóng gói và kiểm tra)

PDF được dựng bằng **Typst** (wheel `typst==0.15.2` trong lockfile có hash `api/requirements.txt`), chạy trong tiến trình con đã giới hạn RAM/CPU/thời gian, **không cần trình duyệt và không cần mạng** lúc dựng. Font nằm trong repo (`scanner/assets/fonts`, DejaVu; Be Vietnam Pro + JetBrains Mono sẽ đi kèm template) và được nhúng đầy đủ nên tiếng Việt hiển thị đúng.

**Self-test** (dựng 1 trang tiếng Việt trong worker, kiểm `%PDF-`, chữ "Đối tượng kiểm thử", font nhúng Type0/FontFile2 thuộc bộ font của ta, và `@preview` bị chặn):

```bash
python -m scanner.pdf.selftest        # chạy ở thư mục gốc repo; in "PDF engine: typst 0.15.2 OK" hoặc lỗi + cách sửa
python3 scripts/setup.py --check      # liệt kê tool + chạy self-test này (native)
```

- **Docker (amd64 + arm64):** `api/Dockerfile` chạy self-test sau khi copy source; lỗi → build FAIL. CI job `pdf-docker` build cả hai kiến trúc (arm64 trên runner arm gốc).
- **Native (macOS, Linux, Windows x64):** `bash setup.sh` cài lockfile rồi chạy self-test; `bash run.sh` in trạng thái `PDF engine` khi khởi động (chỉ cảnh báo, không chặn app).
- **Windows ARM64:** chưa có wheel typst, dùng Python x64 hoặc Docker.
- **Lỗi:** chạy lại `pip install --require-hashes -r api/requirements.txt` (native) hoặc `docker compose build --no-cache` (Docker).

**Nâng cấp bản cũ:** `git pull`, sau đó `docker compose build` (Docker) hoặc `bash setup.sh` (native) để nhận engine mới.
