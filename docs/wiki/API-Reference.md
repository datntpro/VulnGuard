# API Reference

Danh sách endpoint REST lấy từ `api/routes/*.py` và `api/main.py`. Schema chi tiết (request/response) xem ở Swagger UI `http://<host>:8080/docs` hoặc `/openapi.json` của chính instance.

## Quy ước

- Base URL mặc định: `http://127.0.0.1:8080`.
- Xác thực (khi `AUTH_ENABLED=true`): cookie `vg_session` hoặc `Authorization: Bearer <token>` (token lấy từ `POST /api/auth/login`). Xem [[Authentication and Roles|Authentication-and-Roles]].
- Endpoint công khai: `GET /api/auth/status`, `POST /api/auth/login`, `POST /api/auth/setup`, `POST /api/auth/logout`, `GET /api/health`. Ngoài `/api/*` (vd `/docs`, `/openapi.json`, `/static`) middleware không kiểm tra đăng nhập.
- VIEWER: chỉ `GET`/`HEAD`.
- Cột **Quyền**: `ADMIN` = middleware hoặc dependency chỉ cho ADMIN; để trống = mọi user đã đăng nhập (ghi cần ANALYST trở lên).
- Khi `AUTH_ENABLED=false`: mọi request không phải `GET`/`HEAD`/`OPTIONS` tới `/api/pentest`, `/api/webscans`, `/api/domains` bị chặn 403.
- Module tắt bằng feature flag (`FEATURE_COWORKER`, `FEATURE_DOCREVIEW`, `FEATURE_FILE_ASSISTANT`) trả 404.

## Hệ thống

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET | `/api/health` | công khai | `{status, service, deploy_mode}` |
| GET | `/api/features` | | Cờ bật/tắt module |

## Auth và người dùng

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET | `/api/auth/status` | công khai | `auth_enabled`, `setup_required` |
| POST | `/api/auth/setup` | công khai | Tạo ADMIN đầu tiên (chỉ khi chưa có user nào; cần `setup_token`) |
| POST | `/api/auth/login` | công khai | Đăng nhập, trả `token` + đặt cookie `vg_session` và cookie thiết bị `vg_device` (path `/api/auth`). Sai quá 5 lần → 429 + `Retry-After` |
| POST | `/api/auth/logout` | công khai | Thu hồi token hiện tại (`jti`) và xoá cookie; token khác của user vẫn dùng được |
| POST | `/api/auth/logout-all` | | Đăng xuất mọi phiên/token của user (tăng `token_version`) |
| GET | `/api/auth/me` | | User hiện tại |
| POST | `/api/auth/change-password` | | Đổi mật khẩu |
| GET / POST | `/api/auth/users` | ADMIN | Liệt kê / tạo user |
| PATCH / DELETE | `/api/auth/users/{user_id}` | ADMIN | Sửa / xoá user |

## Project, scan, vuln

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET / POST | `/api/projects` | | Liệt kê / tạo project |
| GET / DELETE | `/api/projects/{project_id}` | | Chi tiết / xoá |
| GET / POST | `/api/projects/{project_id}/scans` | | Liệt kê / tạo scan |
| GET | `/api/projects/scans/{scan_id}` | | Chi tiết scan |
| GET | `/api/projects/scans/{scan_id}/progress` | | Tiến độ theo tool |
| GET | `/api/projects/scans/{scan_id}/vulns?severity=&status=&scan_type=` | | Finding |
| GET | `/api/projects/scans/{scan_id}/export?format=` | | Export (xem [[Reports and Exports|Reports-and-Exports]]) |
| GET | `/api/scans/{scan_id}/report?download=` | | Báo cáo HTML |
| GET | `/api/projects/{project_id}/compare?scan_old_id=&scan_new_id=` | | So sánh 2 scan |
| GET | `/api/projects/{project_id}/scan-trend` | | Xu hướng theo scan |
| GET | `/api/projects/{project_id}/approve-check` | | Kiểm tra cổng phát hành |
| GET | `/api/vulns/{vuln_id}` | | Chi tiết finding |
| PATCH | `/api/vulns/{vuln_id}/status` | | Đổi trạng thái triage |
| GET | `/api/vulns/{vuln_id}/dataflow` | | Luồng dữ liệu source → sink |
| GET | `/api/vulns/{vuln_id}/triage-history` | | Lịch sử triage |
| POST / DELETE | `/api/vulns/{vuln_id}/waiver` | | Tạo / bỏ waiver |
| GET | `/api/vulns/{vuln_id}/block-status` | | Finding có chặn phát hành không |
| POST | `/api/vulns/{vuln_id}/reanalyze` | | Chạy lại AI cho 1 finding |

## Dashboard và tuân thủ

| Method | Path | Mô tả |
|---|---|---|
| GET | `/api/dashboard/overview` | Tổng quan |
| GET | `/api/dashboard/compliance?project_id=` | Xem [[Compliance]] |

## Domain, crawl, web scan

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET / POST | `/api/domains` | | Liệt kê / tạo domain |
| GET / DELETE | `/api/domains/{domain_id}` | | |
| GET | `/api/domains/{domain_id}/ownership` | | Lấy token xác minh |
| POST | `/api/domains/{domain_id}/ownership/verify` | | Xác minh |
| GET / POST | `/api/domains/{domain_id}/crawls` | | Liệt kê / chạy crawl |
| GET | `/api/domains/crawls/{crawl_id}` | | |
| GET | `/api/domains/crawls/{crawl_id}/progress` | | |
| POST | `/api/domains/crawls/{crawl_id}/analyze` | | AI phân loại endpoint |
| GET | `/api/domains/crawls/{crawl_id}/endpoints` | | |
| GET | `/api/domains/crawls/{crawl_id}/export?format=` | | |
| GET / POST | `/api/domains/{domain_id}/webscans` | `fuzz=true` cần ADMIN | Liệt kê / chạy web scan |
| GET / DELETE | `/api/webscans/{scan_id}` | | |
| GET | `/api/webscans/{scan_id}/findings?severity=` | | |
| GET | `/api/webscans/{scan_id}/export?format=` | | |
| PATCH | `/api/webscans/findings/{finding_id}/status` | | |

Chi tiết: [[Web Scanning|Web-Scanning]].

## Pentest

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| GET / POST | `/api/pentest/engagements` | đặt `authorized=true` cần ADMIN | |
| GET / PATCH / DELETE | `/api/pentest/engagements/{eng_id}` | như trên | |
| GET / POST | `/api/pentest/engagements/{eng_id}/runs` | | |
| GET | `/api/pentest/runs/{run_id}` | | |
| GET | `/api/pentest/runs/{run_id}/steps` | | |
| GET | `/api/pentest/runs/{run_id}/findings` | | |
| POST | `/api/pentest/runs/{run_id}/stop` | | Kill switch |
| GET | `/api/pentest/runs/{run_id}/approvals` | | |
| POST | `/api/pentest/approvals/{approval_id}/decision` | không phải người khởi chạy run | |
| GET | `/api/pentest/runs/{run_id}/traffic` | | |
| GET | `/api/pentest/engagements/{eng_id}/traffic` | | |
| GET | `/api/pentest/traffic/{traffic_id}` | | |
| POST | `/api/pentest/traffic/{traffic_id}/replay` | | |
| POST | `/api/pentest/findings/{finding_id}/evidence` | | |
| GET | `/api/pentest/proxy/ca.crt` | | CA của MITM proxy |
| GET | `/api/pentest/engagements/{eng_id}/proxy` | | Trạng thái proxy |
| POST | `/api/pentest/engagements/{eng_id}/proxy/start` | | |
| POST | `/api/pentest/engagements/{eng_id}/proxy/stop` | | |

Chi tiết: [[Pentest Agent|Pentest-Agent]].

## Asset, connector, threat intel

| Method | Path | Quyền |
|---|---|---|
| GET | `/api/assets`, `/api/assets/summary`, `/api/assets/{asset_id}` | |
| PATCH / DELETE | `/api/assets/{asset_id}` | |
| POST | `/api/assets/recompute` | |
| GET | `/api/connectors/kinds` | ADMIN |
| GET / POST | `/api/connectors` | ADMIN |
| PATCH / DELETE | `/api/connectors/{cid}` | ADMIN |
| POST | `/api/connectors/{cid}/test`, `/api/connectors/{cid}/sync` | ADMIN |
| GET | `/api/intel/status` | |
| POST | `/api/intel/refresh` | ADMIN |

Chi tiết: [[Assets and Connectors|Assets-and-Connectors]].

## SCM

`/api/scm/connections`, `/api/scm/repos`, `/api/scm/schedules` và các endpoint con. Xem [[SCM Integration|SCM-Integration]].

## Settings, AI, Ollama

| Method | Path | Quyền |
|---|---|---|
| GET / PUT | `/api/ai/settings` | PUT: ADMIN. Trang Settings › AI hợp nhất (thay `/api/ai/config` + `/api/ollama/endpoint`) |
| GET / PUT | `/api/ai/config` | **Deprecated** (gỡ sớm nhất 2027-03-31) → `/api/ai/settings`. PUT: ADMIN |
| POST | `/api/ai/test` | ADMIN |
| POST | `/api/ai/ollama/check` | ADMIN (probe tool-calling / JSON) |
| GET | `/api/ai/models` | ADMIN (khoá tổ chức) hoặc chủ khoá (`credential_id`) |
| GET / POST | `/api/me/ai-credentials` | ANALYST, ADMIN (khoá của chính mình; VIEWER bị 403) |
| POST | `/api/me/ai-credentials/test`, `/api/me/ai-credentials/{id}/test` | chủ khoá |
| PATCH / DELETE | `/api/me/ai-credentials/{id}` | chủ khoá |
| PUT | `/api/me/ai-credentials/{id}/secret` | chủ khoá (xoay khoá) |
| GET | `/api/ai/credentials` | ADMIN (metadata mọi khoá) |
| POST | `/api/ai/credentials/{id}/revoke` | ADMIN |
| GET | `/api/ai/usage?scope=me\|all&days=30` | `me`: không phải VIEWER; `all`: ADMIN |
| POST | `/api/vulns/{id}/reanalyze` | ANALYST, ADMIN |

Chi tiết và mã lỗi: [[Per-user AI keys|AI-Per-User-Keys]]. Endpoint deprecated trả header `Deprecation: true`, `Sunset`, `Link: …; rel="successor-version"`.

| GET / PUT | `/api/settings/scanners` | PUT: ADMIN |
| GET | `/api/settings/scanner-config` | |
| GET / PUT | `/api/settings/report-branding` | PUT: ADMIN |
| POST / DELETE | `/api/settings/report-branding/logo` | (không giới hạn ADMIN) |
| GET | `/api/settings/report-branding/logo-image` | |
| GET / PUT | `/api/settings/sonarqube` | PUT: ADMIN |
| POST | `/api/settings/sonarqube/test` | (không giới hạn ADMIN) |
| GET / PUT | `/api/settings/smtp` | PUT: ADMIN |
| POST | `/api/settings/smtp/test` | (không giới hạn ADMIN) |
| GET / PUT | `/api/ollama/endpoint` | **Deprecated** → `/api/ai/settings`. PUT: ADMIN |
| GET | `/api/ollama/health` | **Deprecated** → `POST /api/ai/ollama/check` |
| GET | `/api/ollama/models` | (chưa deprecated; Settings › AI còn dùng) |
| POST | `/api/ollama/pull` | ADMIN (chưa deprecated) |
| DELETE | `/api/ollama/models/{model_name}` | ADMIN (chưa deprecated) |
| PUT | `/api/ollama/active-model` | **Deprecated** → `/api/ai/settings`. ADMIN |
| GET / PUT | `/api/ollama/vision-model` | **Deprecated** → `/api/ai/settings`. PUT: ADMIN |

## Module tuỳ chọn

| Prefix | Feature flag | Quyền | Endpoint |
|---|---|---|---|
| `/api/docreview` | `FEATURE_DOCREVIEW` | | `doc-types`, `documents`, `documents/{id}`, `documents/{id}/versions`, `documents/{id}/compare`, `versions/{id}`, `versions/{id}/review`, `versions/{id}/progress`, `versions/{id}/send-back`, `versions/{id}/accept`, `versions/{id}/export` |
| `/api/file-assistant` | `FEATURE_FILE_ASSISTANT` | | `health`, `sessions`, `sessions/{id}`, `sessions/{id}/messages`, `sessions/{id}/summaries`, `sessions/{id}/chunks/{file_index}`, `file-types` |
| `/api/coworker` | `FEATURE_COWORKER` | ADMIN | `health`, `folders`, `fs/tree`, `fs/file`, `whitelist`, `fs/suggest`, `fs/apply`, `fs/exec` |
| `/api/coworker/agent` | `FEATURE_COWORKER` | ADMIN | `step`, `health`, `skills`, `route`, `conversations`, `conversations/{conv_id}` |
