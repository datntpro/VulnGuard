# Asset inventory, risk scoring và connector

Mã nguồn: `api/routes/assets.py`, `api/routes/connectors.py`, `api/routes/intel.py`, `scanner/assets/scoring.py`, `scanner/connectors/*`, `scanner/intel/feeds.py`.

## Connector XDR/EDR/NAC

Quản lý ở `/api/connectors` (**chỉ ADMIN**). Secret của connector được mã hoá Fernet trong DB, API chỉ trả gợi ý đã che (`secret_hints`), không trả giá trị thật.

| `kind` | Xác thực | Field secret | Field cấu hình |
|---|---|---|---|
| `TRELLIX_XDR` | OAuth2 client credentials, token lấy tại `iam_url` (mặc định `https://iam.mcafee-cloud.com/iam/v1.1/token`) | `client_id`, `client_secret` | `iam_url`, `scope`, `devices_path`, `detections_path` |
| `TRENDMICRO_VISION_ONE` | Bearer API token; `base_url` theo region (vd `https://api.xdr.trendmicro.com`) | `api_token` | `endpoints_path`, `alerts_path` |
| `FORTINAC` | `POST /api/v2/auth` bằng username/password để lấy token | `username`, `password` | `host_path`, `internet_vlans`, `isolated_vlans`, `verify_tls` |

Endpoint:

| Method | Path | Mô tả |
|---|---|---|
| GET | `/api/connectors/kinds` | Danh sách loại connector và field |
| GET / POST | `/api/connectors` | Liệt kê / tạo (`name`, `kind`, `base_url`, `enabled`, `config`, `secrets`) |
| PATCH / DELETE | `/api/connectors/{cid}` | Sửa (có `clear_secrets`) / xoá |
| POST | `/api/connectors/{cid}/test` | Kiểm tra kết nối |
| POST | `/api/connectors/{cid}/sync` | Đồng bộ asset + alert (chạy nền) |

Đồng bộ là **thủ công**; scheduler của VulnGuard không tự sync connector. Code Trend Micro có hàm cô lập endpoint nhưng **không** có API hay tool nào gọi nó.

## Asset

Asset từ các connector được gộp theo hostname / IP / MAC, kèm software, vuln (CVE) và alert.

| Method | Path | Mô tả |
|---|---|---|
| GET | `/api/assets?sort=risk&min_risk=&source=` | Danh sách |
| GET | `/api/assets/summary` | Thống kê |
| GET | `/api/assets/{id}` | Chi tiết (risk_factors, software, vulns, alerts) |
| PATCH | `/api/assets/{id}` | Sửa `criticality`, `exposure`, `owner`, `tags` (tự tính lại risk) |
| DELETE | `/api/assets/{id}` | Xoá |
| POST | `/api/assets/recompute` | Tính lại risk toàn bộ |

`criticality`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. `exposure`: `INTERNET`, `INTERNAL`, `ISOLATED`, `UNKNOWN`.

## Công thức risk

Điểm 1 vuln trên 1 asset (0 đến 100):

```
score        = 100 × cvss_norm × threat_mult × context_mult
cvss_norm    = cvss / 10              (thiếu CVSS thì dùng 5.0)
threat       = 1.0 nếu CVE thuộc KEV, ngược lại EPSS (thiếu EPSS thì 0.05)
threat_mult  = 0.2 + 0.8 × threat
context_mult = (criticality_w + exposure_w) / 2
```

| criticality | trọng số | exposure | trọng số |
|---|---|---|---|
| CRITICAL | 1.0 | INTERNET | 1.0 |
| HIGH | 0.85 | INTERNAL | 0.7 |
| MEDIUM | 0.6 | ISOLATED | 0.4 |
| LOW | 0.4 | UNKNOWN | 0.7 |

Điểm asset = điểm vuln cao nhất, cộng `2.5` cho mỗi vuln ≥ 50 từ cái thứ hai (tối đa +10). Nếu có alert EDR đang hoạt động: điểm tối thiểu 70, cộng `5` mỗi alert (tối đa +20). Trần 100.

Band: `CRITICAL` ≥ 80, `HIGH` ≥ 60, `MEDIUM` ≥ 35, `LOW` > 0, còn lại `INFO`.

## Threat intel (EPSS / KEV)

- EPSS: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Cache ở `storage/intel/epss.json` và `storage/intel/kev.json`. Không tải được thì dùng cache cũ; không có cache thì scoring vẫn chạy nhưng thiếu enrich.
- `GET /api/intel/status`: trạng thái feed. `POST /api/intel/refresh` (**ADMIN**): tải lại cả hai. Không có lịch tự refresh.

Dữ liệu này cũng có qua [[MCP Server|MCP-Server]].
