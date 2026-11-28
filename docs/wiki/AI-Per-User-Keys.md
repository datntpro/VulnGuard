# Khoá AI theo người dùng / Per-user AI keys

> Hướng dẫn cho ADMIN và người dùng. Khớp với mã nguồn `main` (PR #112–#127). Trang cấu hình: **Settings › AI**. Vận hành khoá: [[AI Key Rotation Runbook|AI-Key-Rotation-Runbook]]. Công ty dùng Kiro: [[Kiro users: Bedrock via IAM Identity Center|AI-Kiro-Bedrock-IAM-Identity-Center]].
> Guide for ADMINs and users. Matches the code on `main`. Settings page: **Settings › AI**. English follows the Vietnamese section ([jump to English](#english)).

---

## Tiếng Việt

### 1. Khoá riêng giúp gì và KHÔNG giúp gì

| Giúp | Không giúp |
|---|---|
| Chia công bằng, quy chi phí về từng người (bảng usage), cô lập sự cố (một khoá lộ → thu hồi một khoá) | **Không tăng tổng thông lượng** nếu nhiều người dùng khoá *cùng* một org Anthropic / OpenAI hoặc *cùng* một tài khoản AWS: rate limit tính theo org/tài khoản (Bedrock: theo tài khoản × Region × model). Muốn tăng thông lượng: nhiều org/tài khoản, xin tăng quota, cross-region inference |

VulnGuard không làm chargeback; bảng usage chỉ để đối soát. Chi phí của khoá riêng do chủ tài khoản provider trả.

### 2. Ai làm được gì

| Vai trò | Khoá riêng (`/api/me/ai-credentials`) | Cấu hình tổ chức & chính sách | Khoá của người khác |
|---|---|---|---|
| ADMIN | Có (khoá của chính mình) | Sửa mọi mục | Chỉ xem **metadata** (chủ, provider, `…4 ký tự cuối`, trạng thái, lần dùng cuối, usage 30 ngày) và **thu hồi**. Không đọc / thử / dùng được key |
| ANALYST | Có | Chỉ xem | Không thấy |
| VIEWER | **Không** (403) | Chỉ xem | Không thấy |

Khoá không bao giờ được trả lại qua API. "Thay khoá" nghĩa là gửi khoá mới (được kiểm tra trước khi thay). Nếu `AUTH` tắt, không có user thật → không dùng được khoá cá nhân (400).

### 3. Người dùng thêm khoá (Settings › AI › **Khoá AI của tôi**)

Provider cho khoá cá nhân: `anthropic`, `bedrock`, `openai`, `openrouter`, `azure_openai`, `gemini`. (`vertex`, `openai_compatible`, Entra, `base_url` tuỳ chỉnh chỉ có ở cấu hình **tổ chức**, ADMIN.)

1. Bấm **Thêm khoá**, chọn provider, dán key, (tuỳ chọn) model, nhãn, region.
2. VulnGuard **kiểm tra trước khi lưu** (một lời gọi tối thiểu tới provider). Sai → không lưu, hiện mã lỗi.
3. Khoá đầu tiên tự thành mặc định. Tối đa **20** khoá/người. Nhãn không được trùng trong cùng provider.
4. Azure OpenAI: chỉ nhập **tên resource** (không phải URL) + `deployment` (+ `api_version`); host `https://<resource>.openai.azure.com` do server dựng.
5. Bedrock: dán **Bedrock API key**, đặt `region` (mặc định `us-east-1`) và model id hoặc inference-profile id. Xem hướng dẫn Kiro/IAM Identity Center.
6. Test giới hạn **5 lần/phút/người** (toàn hệ thống 20/phút) → `429 RATE_LIMITED`.

Không chấp nhận: token OAuth gói Claude.ai (`sk-ant-oat…`) → `AI_KEY_UNSUPPORTED`; khoá < 8 ký tự, có khoảng trắng/ký tự điều khiển → `AI_KEY_INVALID_FORMAT`. JSON service-account không dùng được làm key Gemini.

Đã lưu rồi chỉ sửa được nhãn, model, region, deployment, api_version, mặc định (`PATCH`); đổi model/region đặt lại trạng thái `unknown` cho tới lần test kế. Xoá khoá = xoá secret ngay, giữ dòng "tombstone" 30 ngày để audit/usage còn tra được id, sau đó tự purge (lịch chạy mỗi ngày). Usage event giữ 180 ngày.

### 4. Khoá nào được dùng cho một lần gọi AI (thứ tự)

1. **Chế độ và định tuyến tác vụ** (Settings › AI mục 1–2): `local_only` → Ollama; `hybrid` → theo bảng tác vụ; `cloud_only` → cloud. Document Review và File Assistant luôn local.
2. **Khoá đã ghim vào job** (Pentest run, hội thoại Co-work, scan có `ai_credential_id`): nếu còn `valid|unknown`, đúng chủ, còn được policy cho phép. Bị thu hồi/vô hiệu/không còn được phép → `AI_CRED_REVOKED`. **Không bao giờ tự chuyển sang khoá khác giữa chừng.**
3. **Khoá mặc định của người khởi chạy** (khi `byok` ≠ `off`), lọc theo `allowed`.
4. **Khoá tổ chức** nếu `fallback_to_org` và `byok` ≠ `required` và chưa hết hạn mức tháng / rpm.
5. Không có gì → từ chối `AI_NO_CREDENTIAL`.

Không bao giờ dùng khoá của người khác. Khoá của admin không dùng cho job của người khác. Job hệ thống (không có người khởi chạy, vd lịch quét) dùng khoá tổ chức khi `scheduled_jobs_credential = org`, hoặc khoá của người tạo lịch khi `owner`, hoặc chạy local-only khi `local_only`.

| Công việc | Khoá |
|---|---|
| Quét thủ công / Phân tích lại | Người bấm → khoá tổ chức theo policy |
| Quét theo lịch | Theo `scheduled_jobs_credential` / `ai_credential_policy` của lịch (mặc định: tổ chức) |
| Pentest run | Khoá của người **bắt đầu** run; resume dùng lại đúng khoá; người duyệt khác không đổi được khoá. Khoá mất → run `PAUSED` |
| Co-work | Local → Ollama; Cloud → resolver; Hybrid → dòng "Co-work" của bảng quy tắc (`hybrid.tasks.coworker`, mặc định `local`). Route ghim theo hội thoại; đổi cấu hình không âm thầm đẩy hội thoại cũ lên cloud (`AI_ROUTE_CHANGED`). Route cloud cần model đã qua probe tool-calling (`AI_CLOUD_NO_TOOLS`) |
| Document Review / File Assistant | Chỉ Ollama |

### 5. Chính sách (ADMIN, Settings › AI › **Chính sách khoá & ngân sách**; API `PUT /api/ai/settings` khoá `policy`)

| Trường | Giá trị | Mặc định | Ý nghĩa |
|---|---|---|---|
| `byok` | `allowed` / `required` / `off` | `allowed` | `off`: chặn tạo/dùng khoá riêng (`AI_BYOK_OFF`); `required`: khoá tổ chức không dùng cho job của người |
| `fallback_to_org` | bool | `true` | Cho phép rơi về khoá tổ chức |
| `allowed` | danh sách glob `provider:model` | `[]` (không giới hạn) | Kiểm khi lưu **và** khi gọi; đổi policy có hiệu lực ngay, không xoá khoá. Mẫu không có `:` = `mẫu:*`. Vi phạm → `AI_NOT_ALLOWED` |
| `org_quota.usd_per_user_month` | số ≥ 0 hoặc rỗng | rỗng (không giới hạn) | Trần ước tính USD/người/tháng cho **khoá tổ chức** → `AI_QUOTA` |
| `org_quota.rpm_per_user` | số nguyên | rỗng | Request/phút/người trên khoá tổ chức → `AI_RATE_LIMIT` |
| `user_quota_own_keys.rpm_per_user` | số nguyên | 120 | Bảo vệ server, không phải chi phí |
| `scheduled_jobs_credential` | `org` / `owner` / `local_only` | `org` | Khoá cho job không có người khởi chạy |
| `custom_base_url` | `admin_only` / `off` | `admin_only` | `off` chặn đặt `base_url` mới (kể cả `openai_compatible`) |
| `base_url_allowlist` | danh sách `host`, `host:port`, `*.suffix` | `[]` | Từ PR-7, mỗi mục được kiểm khi lưu (không scheme/path/userinfo, wildcard chỉ ở đầu dạng `*.`) → `422`. Bộ chặn SSRF (`url_guard`) dùng danh sách này cùng env `AI_BASE_URL_ALLOWLIST` và khoá `base_url_allowlist` ở gốc `ai_config.json`. Mục không hợp lệ bị bỏ (fail closed). Mục `host:port` chỉ mở đúng cặp host:port; mục không có cổng không mở cổng ngoài danh sách mặc định. Không bao giờ mở loopback/link-local/metadata. Không nhận `*.com`, `*.co.uk`… |
| `azure_deployment_models` | `{"<resource>/<deployment>": "<model thật>"}` | `{}` | Tên deployment do người dùng đặt nên không dùng để định giá/allowlist. Chưa ánh xạ = `unmapped/<deployment>`: không khớp allowlist cụ thể, tính giá đắt nhất họ OpenAI. Khi `PUT`, trường này là **REPLACE** toàn bộ map; `null` chỉ xoá một mục khi nằm **trong** map đầy đủ được gửi; gửi riêng `{"b": null}` sẽ làm mất các mục còn lại. Muốn xoá một mục: gửi lại map đầy đủ đã bỏ mục đó |

Ghi chú vận hành:
- Mặc định giữ nguyên hành vi trước nâng cấp: BYOK cho phép, khoá tổ chức không giới hạn tới khi bạn đặt trần.
- URL Ollama do ADMIN đặt: chặn metadata/link-local; **cho phép** LAN/loopback, kể cả cổng 80/443 (chủ ý, ADMIN đặt rõ). Cổng thêm: biến `AI_URL_EXTRA_PORTS`.
- Muốn thấy ai dùng gì: `GET /api/ai/usage?scope=all&days=30` (ADMIN) và `GET /api/ai/credentials`. Usage không chứa key; chỉ `…4 ký tự cuối`.
- Nhật ký audit logger `vulnguard.audit.ai`: `ai_cred action=create|rotate|delete|test|revoke_by_admin … hint=…xxxx outcome=…`. Không có key.

### 6. Thu hồi khi nhân sự nghỉ / lộ khoá

1. ADMIN: Settings › AI › danh sách khoá (hoặc `POST /api/ai/credentials/{id}/revoke`). Secret bị xoá ngay.
2. Job đang chạy ghim khoá đó sẽ dừng với `AI_CRED_REVOKED` (Pentest → `PAUSED`).
3. **Việc ở phía provider vẫn phải làm**: khoá đã bị lộ phải bị vô hiệu ở Anthropic Console / AWS IAM, vì thu hồi trong VulnGuard không huỷ khoá ở provider.

### 7. Mã lỗi thường gặp

| Mã | Ý nghĩa / cách xử lý |
|---|---|
| `INVALID_KEY` | Provider từ chối (401). Tạo key mới → Thay khoá |
| `NO_MODEL_ACCESS` | Khoá hợp lệ nhưng không có quyền model, hoặc model id sai (Bedrock: kiểm model access / inference profile) |
| `RATE_LIMITED`, `TIMEOUT`, `NETWORK` | Tạm thời / mạng. Thử lại |
| `BAD_BASE_URL` | URL bị chặn bởi bộ chặn SSRF hoặc sai định dạng |
| `AI_NO_CREDENTIAL` | Không có khoá khả dụng: thêm khoá riêng hoặc nhờ ADMIN bật khoá tổ chức |
| `AI_CRED_REVOKED` | Khoá đã bị thu hồi / vô hiệu / không còn được policy cho phép |
| `AI_NOT_ALLOWED`, `AI_BYOK_OFF` | Policy chặn |
| `AI_QUOTA`, `AI_RATE_LIMIT` | Hết hạn mức tháng / quá rpm của khoá tổ chức |
| `AI_KEY_UNSUPPORTED`, `AI_KEY_INVALID_FORMAT` | Loại/định dạng key không được chấp nhận |
| `AI_CRED_LIMIT`, `AI_CRED_DUPLICATE_LABEL` | Quá 20 khoá / trùng nhãn |
| `AI_CLOUD_NO_TOOLS`, `AI_ROUTE_CHANGED` | Xem Co-work ở trên |

Thông báo lỗi của provider không bao giờ được trả nguyên văn; API chỉ trả mã chuẩn hoá (`detail.code`, `code`, hoặc tiền tố `CODE:` trong `detail` chuỗi).

### 8. Giới hạn đã biết (từ #109)

- Test một provider khác yêu cầu nhập lại key (chủ ý). Thay đổi cosmetic `base_url` bị từ chối trên `/api/ai/settings` khi `custom_base_url=off`.
- Lịch chưa có người tạo (cũ) vẫn có thể bị xoá bởi bất kỳ ai có quyền lịch (có từ trước PR này).
- Anthropic WIF: đường đổi token qua HTTP **chưa được xác minh** end-to-end.
- Pool DB có thể báo `TimeoutError` quanh ~50 lời gọi đồng thời (fail-closed, không lộ dữ liệu).
- Giá model lạ có id dạng `a/b/c` (vd Vertex `publishers/google/models/…`) được tính ở mức đắt nhất (ước lượng cao, an toàn).
- Co-work: launcher chạy `--workers 1`; nhiều worker cần cột `version`/khoá cho từng hội thoại.

### 9. Endpoint deprecated / Deprecated endpoints {#deprecated-endpoints}

Gỡ **không sớm hơn 2027-03-31** (và chỉ sau khi CHANGELOG thông báo). Đến lúc đó hành vi **không đổi**; response chỉ có thêm header `Deprecation: true`, `Sunset: Wed, 31 Mar 2027 00:00:00 GMT`, `Link: <thay-thế>; rel="successor-version"`, và server ghi một dòng WARNING `vulnguard.deprecation` cho mỗi route (một lần/process).

| Cũ | Thay bằng |
|---|---|
| `GET`/`PUT /api/ai/config` | `GET`/`PUT /api/ai/settings` |
| `GET`/`PUT /api/ollama/endpoint`, `PUT /api/ollama/active-model`, `GET`/`PUT /api/ollama/vision-model` | `GET`/`PUT /api/ai/settings` (khoá `ollama`) |
| `GET /api/ollama/health` | `POST /api/ai/ollama/check` |

`GET /api/ollama/models`, `POST /api/ollama/pull`, `DELETE /api/ollama/models/{name}` **chưa deprecated**: trang Settings › AI còn dùng và chưa có endpoint thay thế.

---

## English {#english}

### 1. What per-user keys do and do NOT do

| Does | Does not |
|---|---|
| Fair sharing, per-person cost attribution (usage table), blast-radius isolation (one leaked key → revoke one key) | **Does not raise total throughput** when several people use keys from the *same* Anthropic/OpenAI org or the *same* AWS account: limits are per org/account (Bedrock: per account × Region × model). For more throughput use separate orgs/accounts, quota increases, or cross-region inference |

VulnGuard does no chargeback; the usage table is for reconciliation. A personal key is billed to whoever owns that provider account.

### 2. Who can do what

| Role | Own keys (`/api/me/ai-credentials`) | Org config & policy | Other people's keys |
|---|---|---|---|
| ADMIN | Yes (own keys) | Edit everything | **Metadata only** (owner, provider, last 4 chars, status, last used, 30-day usage) and **revoke**. Cannot read, test or use them |
| ANALYST | Yes | Read-only | Invisible |
| VIEWER | **No** (403) | Read-only | Invisible |

A key is never returned by any API. "Replace" means sending a new key (validated first). With `AUTH` disabled there is no real user, so personal keys are unavailable (400).

### 3. Adding a key (Settings › AI › **My AI keys**)

Providers for personal keys: `anthropic`, `bedrock`, `openai`, `openrouter`, `azure_openai`, `gemini`. `vertex`, `openai_compatible`, Entra and custom `base_url` exist only at **org** level (ADMIN).

1. **Add key**, choose provider, paste the key, optionally model / label / region.
2. VulnGuard **validates before saving** (one minimal provider call). If it fails nothing is stored and a code is shown.
3. The first key becomes the default. Max **20** keys per user; labels are unique per provider.
4. Azure OpenAI: enter the **resource name** (not a URL) + `deployment` (+ `api_version`); the host `https://<resource>.openai.azure.com` is built server-side.
5. Bedrock: paste a **Bedrock API key**, set `region` (default `us-east-1`) and a model id or inference-profile id. See the Kiro / IAM Identity Center guide.
6. Tests are limited to **5/min/user** (20/min globally) → `429 RATE_LIMITED`.

Rejected: Claude.ai subscription OAuth tokens (`sk-ant-oat…`) → `AI_KEY_UNSUPPORTED`; keys < 8 chars or containing whitespace/control chars → `AI_KEY_INVALID_FORMAT`; a service-account JSON cannot be a Gemini key.

After saving you can `PATCH` label, model, region, deployment, api_version and default; changing model/region resets status to `unknown` until the next test. Deleting wipes the secret immediately and keeps a tombstone row for 30 days (so audit/usage can still resolve the id), then a daily job purges it. Usage events are kept 180 days.

### 4. Which key is used for an AI call (order)

1. **Mode and task routing** (Settings › AI sections 1–2): `local_only` → Ollama; `hybrid` → per-task table; `cloud_only` → cloud. Document Review and File Assistant are always local.
2. **The key pinned to the job** (Pentest run, Co-work conversation, scan with `ai_credential_id`) if still `valid|unknown`, owned by the job owner and allowed by policy. Revoked/disabled/not allowed → `AI_CRED_REVOKED`. **It never silently switches to another key mid-job.**
3. **The initiating user's default key** (when `byok` ≠ `off`), filtered by `allowed`.
4. **The org key** if `fallback_to_org` and `byok` ≠ `required` and the monthly/rpm quota is not exhausted.
5. Otherwise refuse with `AI_NO_CREDENTIAL`.

Another user's key is never used; an admin's key is never used for other people's jobs. System jobs (no initiating user, e.g. scheduled scans) use the org key when `scheduled_jobs_credential = org`, the schedule creator's key for `owner`, or run local-only for `local_only`.

| Work | Key |
|---|---|
| Manual scan / re-analyze | The requesting user → org key per policy |
| Scheduled scan | Per the schedule's `ai_credential_policy` / `scheduled_jobs_credential` (default: org) |
| Pentest run | The key of whoever **started** the run; resume reuses it; other approvers cannot switch it. Key gone → run `PAUSED` |
| Co-work | Local → Ollama; Cloud → resolver; Hybrid → the "Co-work" row of the hybrid table (`hybrid.tasks.coworker`, default `local`). The route is pinned per conversation; settings changes never silently push an old conversation to the cloud (`AI_ROUTE_CHANGED`). A cloud route needs a model that passed the tool-calling probe (`AI_CLOUD_NO_TOOLS`) |
| Document Review / File Assistant | Ollama only |

### 5. Policy (ADMIN, Settings › AI › **Key & budget policy**; API `PUT /api/ai/settings`, key `policy`)

Fields, defaults and meanings are listed in the table in the Vietnamese section 5 (same names). Highlights:
- Defaults preserve pre-upgrade behaviour: BYOK allowed, org key unlimited until you set a cap.
- `allowed` is checked on save **and** on every call; changing it takes effect immediately without deleting keys.
- `base_url_allowlist` entries are validated on save since PR-7 (`host`, `host:port`, `*.suffix`; no scheme/path/userinfo) → `422`. The SSRF guard (`url_guard`) consumes this list together with the `AI_BASE_URL_ALLOWLIST` env var and a top-level `base_url_allowlist` key in `ai_config.json`. Invalid entries from any source are dropped (fail closed). A `host:port` entry opens only that exact host:port pair; a bare entry does not open non-default ports. Loopback, link-local and metadata addresses stay blocked. Shared-suffix wildcards such as `*.com` or `*.co.uk` are rejected.
- An ADMIN may point Ollama at a LAN/loopback address, including ports 80/443 (intentional, explicit). Metadata/link-local ranges are always blocked. Extra ports: `AI_URL_EXTRA_PORTS`.
- `azure_deployment_models` is **REPLACE** on `PUT`. `null` removes an entry only inside a full map; sending `{"b": null}` alone drops all other entries. To remove one entry, resend the full map without it.
- Who used what: `GET /api/ai/usage?scope=all&days=30` and `GET /api/ai/credentials` (ADMIN), metadata and last-4 only. Audit logger `vulnguard.audit.ai` never contains keys.

### 6. Offboarding / leaked key

1. ADMIN: Settings › AI › key list (or `POST /api/ai/credentials/{id}/revoke`). The secret is wiped immediately.
2. Jobs pinned to it stop with `AI_CRED_REVOKED` (Pentest → `PAUSED`).
3. **Provider side is still your job**: a leaked key must be disabled in the Anthropic Console / AWS IAM; revoking in VulnGuard does not cancel the key at the provider.

### 7. Common codes

See the Vietnamese table (section 7); codes are identical. Provider error text is never returned, only normalised codes.

### 8. Known limitations (from #109)

Re-test with another provider needs the key retyped (by design); cosmetic `base_url` changes are refused on `/api/ai/settings` when `custom_base_url=off`; legacy schedules with no creator can be deleted by anyone with schedule rights (pre-existing); the Anthropic WIF HTTP token exchange is **unverified** end to end; the DB pool may raise `TimeoutError` near ~50 concurrent calls (fails closed); unknown slashed model ids (e.g. Vertex `publishers/google/models/…`) are priced at the top tier; Co-work runs with `--workers 1`.

### 9. Deprecated endpoints

Removal **no earlier than 2027-03-31**, and only after the CHANGELOG announces it. Until then behaviour is **unchanged**; responses just gain `Deprecation: true`, `Sunset: Wed, 31 Mar 2027 00:00:00 GMT` and `Link: <successor>; rel="successor-version"`, and the server logs one WARNING (`vulnguard.deprecation`) per route per process. Mapping: see the Vietnamese table. `GET /api/ollama/models`, `POST /api/ollama/pull` and `DELETE /api/ollama/models/{name}` are **not** deprecated because the Settings › AI page still uses them and no replacement exists.
