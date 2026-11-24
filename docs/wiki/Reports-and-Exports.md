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
