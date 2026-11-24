# Quét web (Katana + Nuclei)

Mã nguồn: `api/routes/domains.py`, `api/routes/webscans.py`, `scanner/ownership.py`, `scanner/crawler/*`.

Luồng: **khai báo domain → xác minh quyền sở hữu → (tuỳ chọn) crawl → web scan → triage / export**.

> Chỉ quét domain bạn sở hữu hoặc được uỷ quyền. Khi `AUTH_ENABLED=false`, mọi thao tác ghi trên `/api/domains` và `/api/webscans` bị khoá.

## 1. Khai báo domain

`POST /api/domains` với `name`, `url` (thiếu scheme thì tự thêm `https://`), `description`.

## 2. Xác minh quyền sở hữu (bắt buộc)

1. `GET /api/domains/{id}/ownership` sinh token dạng `vulnguard-<32 hex>` và trả hướng dẫn.
2. Chọn một cách:
   - **DNS TXT**: thêm bản ghi TXT trên host của domain: `vulnguard-verify=<token>`.
   - **File**: đặt `https://<host>/.well-known/vulnguard.txt` chứa `<token>`.
3. `POST /api/domains/{id}/ownership/verify`. Thành công thì domain có `ownership_verified=true` và `ownership_method` (`dns_txt` hoặc `well_known`).

Chưa xác minh thì crawl và web scan trả 403.

> Cách DNS TXT dùng thư viện `dnspython` (`import dns.resolver`). `api/requirements.txt` không khai báo gói này; nếu môi trường không có `dnspython`, bước kiểm DNS luôn thất bại và chỉ còn cách file `.well-known`.

## 3. Crawl (Katana)

`POST /api/domains/{id}/crawls`:

| Trường | Mặc định | Giới hạn |
|---|---|---|
| `depth` | 3 | 1 đến 10 |
| `max_urls` | 2000 | 10 đến 20000 (áp dụng khi parse output) |
| `js_crawl` | true | thêm `-jc` (đọc endpoint trong file JS, không cần headless browser) |
| `include_subdomains` | false | `-fs rdn` nếu true, `-fs fqdn` nếu false |
| `exclude_patterns` | [] | regex, truyền vào `-fr` |
| `timeout` | 600 giây | 30 đến 3600 |
| `run_ai_analysis` | false | sau crawl dùng Ollama phân loại endpoint nhạy cảm + gợi ý WAF |

Lệnh Katana: `katana -u <url> -d <depth> -silent -jsonl -fx -aff -c 10 -p 10 -timeout 10 -retry 1 -fs ...`. Lưu ý `-aff` là tự điền form, và lệnh không đặt rate limit.

Theo dõi: `GET /api/domains/crawls/{crawl_id}/progress`, xem endpoint: `GET /api/domains/crawls/{crawl_id}/endpoints?method=&search=`. Chạy AI sau: `POST /api/domains/crawls/{crawl_id}/analyze`.

Export crawl: `GET /api/domains/crawls/{crawl_id}/export?format=json|sitemap_xml|waf_baseline|modsecurity`.

Mỗi domain giữ tối đa `MAX_CRAWLS_PER_DOMAIN` crawl (mặc định 5).

## 4. Web scan (Nuclei)

`POST /api/domains/{id}/webscans`:

```json
{
  "crawl_id": null,
  "severities": ["critical","high","medium","low"],
  "tags": [],
  "exclude_tags": ["dos","fuzz","intrusive","bruteforce"],
  "fuzz": false,
  "rate_limit": 10,
  "authorized": true
}
```

| Trường | Ý nghĩa |
|---|---|
| `crawl_id` | Không có: chỉ quét URL gốc của domain. Có: quét URL gốc + mọi endpoint của crawl đó (tối đa 5000 URL). Crawl phải `COMPLETED` và thuộc domain |
| `severities` | Chọn trong `critical`, `high`, `medium`, `low`, `info` |
| `tags` / `exclude_tags` | Truyền vào `-tags` / `-etags` (tối đa 20, mỗi tag 60 ký tự). `exclude_tags` mặc định **rỗng** |
| `fuzz` | Thêm `-dast` (fuzzing tham số). **Chỉ ADMIN** |
| `rate_limit` | Mặc định 10 req/s, từ 1 đến 500 |
| `authorized` | Bắt buộc `true` (xác nhận bạn có quyền quét) |

Điều kiện khác: phải cài `nuclei`, mỗi domain chỉ 1 web scan chạy cùng lúc, giữ tối đa `MAX_WEBSCANS_PER_DOMAIN` (mặc định 5), timeout `NUCLEI_TIMEOUT_MINUTES` (mặc định 60).

Lệnh Nuclei: `nuclei -l <targets> -jsonl -silent -nc -duc -severity ... -rl <rate> -c 10 -timeout 10 -retries 1 [-tags] [-etags] [-dast]`. `-duc` tắt kiểm tra update, nên template phải được cập nhật trước (`nuclei -update-templates`).

Trước Nuclei, VulnGuard tự kiểm tra **security header** cho từng host: thiếu HSTS (medium), CSP (medium), X-Frame-Options (low), X-Content-Type-Options (low), Referrer-Policy (info).

Finding được gộp trùng theo `template_id|matcher_name|matched_at`.

## 5. Kết quả, triage, export

- `GET /api/webscans/{scan_id}`: trạng thái, `progress`, `summary`.
- `GET /api/webscans/{scan_id}/findings?severity=`.
- `PATCH /api/webscans/findings/{finding_id}/status` với `OPEN`, `FALSE_POSITIVE`, `ACCEPTED`, `FIXED`.
- `GET /api/webscans/{scan_id}/export?format=json|csv|html`. Bản HTML in ra PDF bằng trình duyệt.
- `DELETE /api/webscans/{scan_id}` (không xoá được scan đang chạy).

Thời gian trong file export ghi theo UTC.
