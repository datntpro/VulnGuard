# Knowledge Base (DB tri thức lỗ hổng)

Mã nguồn: `scanner/knowledge/store.py`, `scanner/knowledge/build.py`, `scanner/knowledge/updater.py`, `api/routes/knowledge.py`, `.github/workflows/kb-build.yml`.

Knowledge Base (KB) là cơ sở dữ liệu lỗ hổng từ **nguồn mở công khai**, dùng để **làm giàu kết quả scan** (fix version, CWE, tham chiếu) và **xếp ưu tiên triage** (EPSS, CISA KEV). KB được phân phối theo mô hình feed-update giống **Trivy DB / nuclei-templates**: vendor build hằng ngày qua CI → publish bản snapshot ký `sha256` → máy đã cài tự tải về, verify và hoán đổi nguyên khối.

> **Local-first:** KB chỉ chứa dữ liệu công khai. Quá trình cập nhật chỉ **tải xuống** từ GitHub Releases, **không gửi** bất kỳ dữ liệu nào từ máy bạn đi đâu.

## Nguồn dữ liệu

| Nguồn | Nội dung | Dùng để |
|---|---|---|
| **OSV** (osv.dev) | Advisory CVE/GHSA theo ecosystem (PyPI, npm, Go, Maven, RubyGems, crates.io, Packagist, NuGet) + khoảng version bị ảnh hưởng và `fixed` | fix version, CWE, GHSA, tham chiếu |
| **EPSS** (FIRST) | Xác suất một CVE bị khai thác trong 30 ngày tới (0–1) + percentile | xếp ưu tiên theo khả năng bị khai thác |
| **CISA KEV** | Danh mục CVE **đang bị khai thác thực tế**, kèm cờ ransomware và hạn khắc phục | ưu tiên fix cao nhất |

File KB là một SQLite riêng tại `<storage>/knowledge/kb.sqlite` (tách khỏi DB ứng dụng) gồm bảng `advisory`, `epss`, `kev`, `meta`.

## Cập nhật tri thức

### Máy đã cài tự cập nhật (online)

- Scheduler nội bộ (`api/services/scheduler.py`) kiểm tra manifest mỗi `KB_UPDATE_INTERVAL_HOURS` (mặc định 24h) khi `KB_AUTO_UPDATE=true`.
- Luồng: đọc `kb-manifest.json` → so version → tải `kb.sqlite.gz` → **verify `sha256`** → giải nén → **hoán đổi nguyên khối** (giữ bản `.bak` để rollback). Không tải lại nếu version local đã mới nhất.
- Cập nhật tay (chỉ ADMIN): nút **Cập nhật ngay** ở Settings → 📚 Tri thức, hoặc `POST /api/knowledge/update` (thêm `?force=true` để tải lại cả khi đã mới nhất).

### Import offline / air-gap

Môi trường cô lập không ra Internet: tải `kb.sqlite.gz` từ máy khác rồi upload ở Settings → 📚 Tri thức, hoặc `POST /api/knowledge/import` (multipart `file`, tùy chọn `sha256`). Hệ thống kiểm tra tính hợp lệ (mở được bảng `advisory`) trước khi hoán đổi.

### Vendor build hằng ngày (CI)

`.github/workflows/kb-build.yml` chạy cron **14:17 UTC** (sau khi EPSS publish ~13:30 UTC) hoặc kích hoạt tay (`workflow_dispatch`):

1. `python -m scanner.knowledge.build kb.sqlite` — nạp OSV + EPSS + KEV.
2. Nén `kb.sqlite.gz`, tính `sha256`, sinh `kb-manifest.json` (`version`, `built_at`, `sha256`, `url`, `advisory_count`).
3. Publish lên GitHub Releases tag `kb-latest` (xoá release cũ để link `download/kb-latest/...` luôn trỏ bản mới nhất).

> Cần bật quyền ghi cho Actions: **Settings → Actions → General → Workflow permissions → Read and write**.

## Làm giàu & nâng ưu tiên khi scan

Sau khi orchestrator gộp findings, `scanner.knowledge.store`:

1. **`enrich_findings`** — với mỗi finding SCA (có CVE hoặc package+ecosystem), điền **chỉ vào ô trống** `fixed_version` / `cwe` / `cvss_score` (không ghi đè dữ liệu scanner), và gắn `epss`, `kev`.
2. **`prioritize_findings`** — nâng mức ưu tiên theo tri thức khai thác (chỉ **nâng**, không hạ):

   | Điều kiện | Mức tối thiểu |
   |---|---|
   | KEV + ransomware | `CRITICAL` |
   | CISA KEV | `HIGH` |
   | EPSS ≥ 0.5 | `HIGH` |

   Khi nâng, lưu `severity_original` + `priority_reason` để kiểm toán.

Các trường này được lưu trong `raw_output._vulnguard_kb` (không thêm cột DB) và trả qua `VulnOut`. Giao diện hiển thị badge **🔥 KEV**, **💀 Ransomware**, **EPSS %** cạnh severity (bảng vuln, modal chi tiết) và trong báo cáo HTML; finding được nâng có mũi tên **↑** kèm lý do.

## API

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET | `/api/knowledge/status` | công khai | version, `advisory_count`, `epss_count`, `kev_count`, cấu hình auto-update |
| POST | `/api/knowledge/update?force=` | ADMIN | kiểm tra manifest và tải bản mới |
| POST | `/api/knowledge/import` | ADMIN | import offline `kb.sqlite`/`.gz` |
| POST | `/api/knowledge/enrich` | công khai | tra cứu làm giàu 1 CVE/package (`{cve, ecosystem, package}`) |

## Cấu hình

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `KB_MANIFEST_URL` | `…/releases/download/kb-latest/kb-manifest.json` | URL manifest vendor; để trống = tắt auto-update |
| `KB_AUTO_UPDATE` | `true` | bật kiểm tra + tải bản mới theo lịch |
| `KB_UPDATE_INTERVAL_HOURS` | `24` | chu kỳ kiểm tra |

Xem thêm [[Scanning and Triage|Scanning-and-Triage]] và [[Configuration]].
