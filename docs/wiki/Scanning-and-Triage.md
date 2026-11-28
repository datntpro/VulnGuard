# Quét mã nguồn và triage

Mã nguồn: `api/routes/scans.py`, `scanner/orchestrator.py`, `scanner/scanners/*`, `api/services/triage.py`, `api/routes/compare.py`.

## Luồng quét

1. Tạo Project: `POST /api/projects` (`name`, `description`, `language_stacks`).
2. Tạo scan: `POST /api/projects/{project_id}/scans` với:
   ```json
   {"scan_path": "/duong/dan/ma-nguon", "scan_types": ["SAST","SCA","SECRETS","IAC"], "run_ai_analysis": true}
   ```
   - `scan_path` phải nằm trong `SCAN_ALLOWED_ROOTS` (mặc định `/workspace` ở Docker, thư mục home ở native), nếu không API trả 400.
   - `scan_path` là đường dẫn trên máy chạy VulnGuard (Native) hoặc trong container (Docker, ví dụ `/workspace/my-app`).
   - `scan_types` mặc định `SAST`, `SCA`, `SECRETS`, `IAC`. `CONTAINER` phải chọn thêm.
   - Hoặc quét repo GitHub/GitLab qua [[SCM Integration|SCM-Integration]].
3. Scan chạy nền. Theo dõi `GET /api/projects/scans/{scan_id}/progress` (UI poll mỗi 2 giây): % hoàn thành, trạng thái từng tool, số finding.
4. Scanner chạy **song song**, kết quả gộp trùng theo `fingerprint` = sha256 của `tool:rule_id:file:line:title`.
5. Nếu `run_ai_analysis=true`, AI triage chạy nền sau khi scan xong (theo [[AI provider|Configuration]]).
6. Mỗi project giữ tối đa `MAX_SCANS_PER_PROJECT` scan (mặc định 5). Scan cũ nhất bị xoá khi tạo scan mới.

Scan đang `PENDING`/`RUNNING` khi app restart sẽ chuyển `FAILED`.

## Công cụ theo loại scan

| Loại | Tool (key trong Settings) | Lệnh / cách chạy |
|---|---|---|
| SAST | `bandit` | `bandit -r <path> -f json -ll` (mức `-ll` = từ MEDIUM trở lên) |
| SAST | `semgrep` | Luôn chạy bundled rules `scanner/rules/python-security.yaml`. Nếu kết nối được `semgrep.dev:443` thì thêm `p/security-audit`, `p/owasp-top-ten` và ruleset theo ngôn ngữ phát hiện (`p/python`, `p/javascript`, `p/nodejs`, `p/typescript`, `p/react`, `p/java`, `p/golang`, `p/php`, `p/ruby`). Chạy với `--dataflow-traces --metrics=off` |
| SAST | `sonar-scanner` | Chỉ chạy khi có `SONARQUBE_URL` + `SONARQUBE_TOKEN` + binary `sonar-scanner` |
| SCA | `trivy` | `trivy fs --scanners vuln` |
| SCA | `pip-audit` | Chạy cho từng `requirements*.txt`, `Pipfile.lock`, `pyproject.toml` với `--no-deps` |
| SECRETS | `gitleaks` | `gitleaks detect --no-git --redact` |
| SECRETS | `detect-secrets` | Dùng Python API với bộ plugin cố định (AWS, GitHub, GitLab, JWT, OpenAI, private key, Slack, Stripe, entropy…) |
| IAC | `checkov` | `checkov -d <path>` (bỏ `CKV_DOCKER_2`, `CKV_DOCKER_3`) |
| IAC | `trivy-iac` | `trivy fs --scanners misconfig`. **Hiện luôn bị bỏ qua**, xem [[Security and Known Limitations|Security-and-Known-Limitations]] |
| IAC | `hadolint` | Mỗi file `Dockerfile*` |
| CONTAINER | `trivy` | `trivy image` cho từng `image:` tìm thấy trong `docker-compose*.yml/yaml` |
| CONTAINER | `grype` | `grype dir:<path>` |

**Bundled rules (13, offline)** trong `scanner/rules/python-security.yaml`: `sql-injection-string-concat`, `sql-injection-format`, `subprocess-shell-true`, `os-system-injection`, `pickle-loads`, `yaml-unsafe-load`, `weak-hash-md5`, `weak-hash-sha1`, `hardcoded-password-variable`, `open-with-user-input`, `flask-debug-true`, `django-debug-true`, `requests-with-user-url`. Mỗi rule có fixture trong `tests/fixtures/semgrep_rules/`. Lưu ý: semgrep mặc định (`.semgrepignore` built-in) **bỏ qua thư mục `tests/` và `test/`** của repo được quét — finding trong các thư mục đó sẽ không xuất hiện.

Secrets: finding có giá trị công khai/placeholder (Google OAuth client ID `.apps.googleusercontent.com`, `changeme`, `placeholder`, `dummy`, `example`, `<...>`, `${...}`, `test_key`…) bị hạ xuống `INFO`; finding nằm trong đường dẫn test/fixture/example/mock/spec bị hạ xuống `LOW`. Mô tả finding có thêm dòng `[Giảm FP]`.

## Tính trung thực của kết quả

Trước khi chạy, orchestrator kiểm tra tool có trong `PATH` (`which <tool>`). Tool thiếu được ghi `status: "skipped"` thay vì "0 lỗi". Summary của scan có `tools_skipped`, `tools_errored` và `scan_warning`. Báo cáo HTML và PDF có mục **"Công cụ đã dùng"** liệt kê mọi tool kèm trạng thái ✅ OK / ⊘ BỎ QUA / ❌ LỖI / ◐ MỘT PHẦN, và banner cảnh báo ở phần tóm tắt khi có tool không chạy đủ (scan cũ chưa lưu `scanner_logs` thì không có mục này). Chỉ tin "0 lỗi" khi mọi tool đều `ok`.

Bật/tắt từng tool: Settings → Scanner Tools (`PUT /api/settings/scanners`).

## Triage (kiểu Checkmarx)

| Trạng thái | Ý nghĩa | Quy tắc |
|---|---|---|
| `OPEN` | Cần xác minh (To Verify), mặc định | |
| `CONFIRMED` | Đã xác nhận lỗi thật | |
| `URGENT` | Đã xác nhận, khẩn cấp | |
| `PROPOSED_NE` | Đề xuất không khai thác được | |
| `NOT_EXPLOITABLE` | Chốt không khai thác được | Chỉ ADMIN, bắt buộc ghi chú |
| `ACCEPTED` | Chấp nhận rủi ro | Bắt buộc ghi chú |
| `FALSE_POSITIVE` | Cũ, coi như `NOT_EXPLOITABLE` | |
| `FIXED` | Đã sửa | |

- Trạng thái "còn mở" (tính vào rủi ro, chặn approve): `OPEN`, `CONFIRMED`, `URGENT`, `PROPOSED_NE`.
- Đổi trạng thái: `PATCH /api/vulns/{id}/status` với `{"status": "...", "note": "..."}`. Mỗi lần đổi ghi `TriageEvent` (audit), xem bằng `GET /api/vulns/{id}/triage-history`.
- **Kế thừa qua scan**: khi scan mới xong, finding có cùng fingerprint trong project được giữ trạng thái + ghi chú triage của lần trước. `first_seen_at` / `first_seen_scan_id` cho biết finding **Mới** hay **Tái xuất hiện**.
- Waiver: `POST /api/vulns/{id}/waiver`, `DELETE /api/vulns/{id}/waiver`.
- AI phân tích lại 1 finding bằng cloud: `POST /api/vulns/{id}/reanalyze`.

## Làm giàu & nâng ưu tiên từ Knowledge Base

Sau khi gộp findings, orchestrator đối chiếu với [[Knowledge Base|Knowledge-Base]] (OSV + EPSS + CISA KEV):

- **Làm giàu**: điền `fixed_version` / `cwe` / `cvss_score` vào ô còn trống của finding SCA (không ghi đè dữ liệu scanner); gắn thêm `epss` và `kev`.
- **Nâng ưu tiên** (chỉ nâng, không hạ): KEV + ransomware → tối thiểu `CRITICAL`; CISA KEV → tối thiểu `HIGH`; EPSS ≥ 0.5 → tối thiểu `HIGH`. Lưu `severity_original` + `priority_reason` để kiểm toán.

Giao diện hiển thị badge **🔥 KEV**, **💀 Ransomware**, **EPSS %** cạnh severity (bảng vuln, modal, báo cáo HTML); finding được nâng có mũi tên **↑** kèm lý do. Hoạt động cả khi KB chưa có (bỏ qua, không lỗi).

## Cổng approve deploy

- `GET /api/projects/{project_id}/approve-check?scan_id=...` trả `APPROVED` hoặc `BLOCKED` theo số finding còn mở có severity ≥ `BLOCK_SEVERITY_THRESHOLD` (mặc định `HIGH`).
- `GET /api/vulns/{id}/block-status` cho từng finding.
- Lưu ý: approve-check **không** xét tool bị bỏ qua. Scan có tool `skipped` vẫn có thể ra `APPROVED`.

## Lịch sử và so sánh scan

- `GET /api/projects/{project_id}/scan-trend`: số finding theo severity qua các lần scan `COMPLETED`, cũ đến mới.
- `GET /api/projects/{project_id}/compare?scan_old_id=...&scan_new_id=...`: so sánh 2 scan, chia **Mới / Tái xuất hiện / Đã khắc phục / Chưa đánh giá (Not Evaluated)**. "Not Evaluated" là finding thuộc loại scan không chạy lại ở scan mới, nên không bị báo nhầm là đã sửa.

## Đồ thị data-flow

`GET /api/vulns/{id}/dataflow` trả các node source → propagation → sink (file, dòng, đoạn code) rút từ `dataflow_trace` của Semgrep taint-mode. Finding từ tool khác không có dữ liệu này.

## CLI

```bash
python -m scanner.cli scan --path /workspace --project "My App" --stacks java,python,terraform [--no-ai] [--api http://localhost:8080]
```

CLI gọi API qua HTTP. Code CLI hiện không gửi token đăng nhập, nên với `AUTH_ENABLED=true` (mặc định) các lệnh gọi API sẽ bị 401.
