# Changelog

## Unreleased

### Added — #101 PR-B: smoke scanner trong image CI
- `python -m scanner.scanners.selftest` chạy từng scanner đóng gói (semgrep bundled rules, bandit, checkov, hadolint, gitleaks, detect-secrets, trivy-iac + `--version` của trivy/grype/pip-audit) trên fixture có lỗi đã biết và đòi số finding tối thiểu; bước mới trong job `pdf-docker` (amd64 + arm64, non-root, rootfs read-only, không mạng). Tool hỏng im lặng (vd gitleaks 8.18.4 từ chối `--quiet`) làm CI đỏ.
- gitleaks và trivy-iac tạm `--xfail` (TODO #120); trivy SCA/pip-audit cần tải DB nên chỉ kiểm `--version`.

### Fixed — #101 PR-A: sửa 12/13 bundled semgrep rule
- 8 rule không bao giờ khớp (`sql-injection-format`, `subprocess-shell-true`, `pickle-loads`, `yaml-unsafe-load`, `weak-hash-md5`, `weak-hash-sha1`, `open-with-user-input`, `requests-with-user-url`) vì các `pattern` thay thế bị AND thay vì `pattern-either`; 4 rule khớp thiếu/thừa (`sql-injection-string-concat` bỏ sót `"…'" + x + "'"`, `hardcoded-password-variable` bỏ sót `DB_PASSWORD = "…"` và báo nhầm tên biến môi trường/URL, `flask-debug-true` bỏ sót `app.run(host=…, debug=True)`, `os-system-injection` báo nhầm lệnh hằng). `django-debug-true` giữ nguyên.
- Thêm 13 fixture chú thích `tests/fixtures/semgrep_rules/<rule-id>.py` (`# ruleid:` / `# ok:`) và `tests/test_semgrep_bundled_rules.py` (validate YAML, mỗi rule phải có fixture, khớp chính xác không thiếu/thừa, mỗi rule ≥1 true positive). Job `test` của CI cài semgrep từ `docker/scanners/semgrep.txt` và đặt `VG_REQUIRE_SEMGREP=1` để test không bị skip âm thầm.
- Lưu ý: semgrep mặc định bỏ qua thư mục `tests/` khi quét thư mục, nên test copy fixture ra thư mục tạm.

### Fixed — AI PR-6 verify (S1/S2)
- **S1**: khoá Azure OpenAI định dạng mới (84 ký tự base62, `…JQQJ99…`) được che ở mọi đường dùng chung `_SECRET_PATTERNS` (prompt triage/pentest/Co-work, log, thông điệp lỗi, transcript Pentest): pattern cấu trúc `52+JQQJ99+26` và `api-key`/`AZURE_OPENAI_API_KEY` + 80–90 ký tự base62 (đều tuyến tính).
- **S2 giá**: `ai_prices` khớp model id CHÍNH XÁC (sau chuẩn hoá tiền tố provider/hậu tố phiên bản-ngày), không khớp chuỗi con/tiền tố nữa — `o3-pro` ($20/$80) và `o3-deep-research` ($10/$40) không còn bị tính như `o3`. Model lạ → mức đắt nhất của họ provider (anthropic/bedrock $5/$25, openai-family $20/$80, gemini/vertex $5/$30); không rõ provider → đắt nhất toàn bảng.
- **S2 Azure**: tên deployment do user đặt không còn quyết định allowlist/giá. ADMIN ánh xạ `policy.azure_deployment_models {"<resource>/<deployment>": "<model thật>"}`; chưa ánh xạ = `unmapped/<deployment>` (không khớp allowlist cụ thể, giá openai-family đắt nhất). Probe lấy model nền Azure báo về (`real_model`) và từ chối `NO_MODEL_ACCESS` nếu không nằm trong allowlist; Meter tính giá theo model đắt hơn giữa ánh xạ và model Azure báo về. **Lưu ý nâng cấp:** deployment Azure chưa ánh xạ nên tính giá đắt cho tới khi ADMIN ánh xạ; allowlist cụ thể (không phải `azure_openai:*`) chặn deployment chưa ánh xạ.

### Fixed — AI PR-6 re-verify
- Probe và Meter kiểm allowlist Azure theo id gốc HOẶC id đã chuẩn hoá (`gpt-4o-2024-08-06` khớp mục `azure_openai:gpt-4o`; `gpt-4o-mini-…` không khớp; chỉ áp cho Azure). `policy.azure_deployment_models` giờ là REPLACE khi lưu (ADMIN xoá được mục; `{}` xoá hết; giá trị `null` xoá một mục; không gửi key = giữ nguyên). Marker `unmapped/<tên>` được giữ qua chuẩn hoá giá → luôn tính mức đắt nhất dù tên trông rẻ; chuẩn hoá chỉ bỏ tiền tố provider đã biết (`openai/`, `anthropic/`, `google/`, `azure/`…), không bỏ mọi `xxx/`. Ghi chú: `PUT /api/ai/config` (legacy) vẫn nhận `policy` (chỉ ADMIN).

### Added — AI PR-6: mở rộng provider (Refs #109)
- **Provider mới** (qua `resolve()`/`open_client()`, family `openai` nên Pentest `LLMDriver`, triage, probe, Meter dùng chung): **Azure OpenAI** (`azure_openai`: key theo deployment, hoặc Entra client-credentials cho org; tham số `endpoint`/`deployment`/`api_version`/`tenant_id`/`client_id`), **Gemini API** (`gemini`, endpoint OpenAI-compatible cố định của Google), **Vertex AI** (`vertex`, chỉ ADMIN/org: service-account JSON; tham số `project`/`location`), **OpenAI-compatible** tuỳ chỉnh (`openai_compatible`, chỉ ADMIN: `base_url` + `model`). **OpenRouter** giữ nguyên (đã hỗ trợ), nhãn usage/`ai_provider` theo provider thật. Không có Kiro/Copilot/GitHub Models (D5/D6); công ty dùng Kiro: Bedrock API key theo người qua IAM Identity Center (hướng dẫn ở PR-7).
- **User (BYOK)**: thêm `azure_openai` (user chỉ đưa TÊN resource + deployment + api_version; host `https://<resource>.openai.azure.com` do server dựng, đổi endpoint qua PATCH không được) và `gemini`. `vertex` / `openai_compatible` / Entra chỉ cấu hình org (D4). Token OAuth `sk-ant-oat…` bị từ chối ở MỌI đường lưu (user và `PUT /api/ai/config`) với `AI_KEY_UNSUPPORTED`.
- **An toàn đích gửi khoá**: `api/services/ai_provider_params.py` kiểm chặt endpoint Azure (`<resource>.openai.azure.com|cognitiveservices.azure.com|openai.azure.us`, không path/port/userinfo/query), deployment, api-version, GUID tenant/client, project/location GCP, base_url — khi lưu, khi test và LẠI lúc dựng client. Host dựng từ nhãn đã kiểm (không nối chuỗi thô). Azure/Vertex/OpenAI-compatible đi qua `url_guard` (resolve + deny-list + **ghim IP** ở mỗi request, không redirect, `trust_env=False`); Gemini/OpenRouter (host cố định) dùng client không proxy env, không redirect. `classify()` nhận ra guard bị SDK bọc (`APIConnectionError.__cause__`) → `BAD_BASE_URL`. Các tham số mới (`tenant_id`, `client_id`, cùng `endpoint/deployment/api_version/project/location/base_url`) nằm trong **envelope** của credential: sửa DB không đổi được nơi khoá được gửi tới.
- **Token ngắn hạn không thêm SDK** (`api/services/ai_oauth.py`): Entra → `login.microsoftonline.com`, Google SA → JWT RS256 ký bằng `cryptography` gửi tới `oauth2.googleapis.com` (host cố định; `token_uri` trong file bị bỏ qua), cache RAM tới hết hạn − 60s, lỗi chuẩn hoá (`INVALID_KEY`) không kèm body provider.
- **Probe**: mã chuẩn hoá như cũ; Azure/Vertex bỏ bước liệt kê model (khoá theo deployment / không có `/models`), endpoint OpenAI-compatible không có `/models` (404/405) vẫn probe chat + tools. Danh sách model: `STATIC_MODELS` thêm Azure/Gemini/Vertex; Gemini lấy từ API (bỏ tiền tố `models/`).
- **Config**: `ai_config.json` thêm section `azure_openai`, `gemini`, `vertex`, `openai_compatible` (key mã hoá như các provider khác; `public_config` không trả key, hint Vertex rỗng); `_TEST_FIELDS` của `POST /api/ai/test` nhận `endpoint/deployment/api_version/tenant_id/client_id/project/location` (đổi nơi gửi ⇒ phải gửi lại key). `policy.custom_base_url=off` chặn cả `openai_compatible.base_url`.
- **Giá/Meter**: `ai_prices.py` thêm `gpt-4o-mini`, `gpt-4.1(-mini)`, `o3`, `o4-mini`, `gemini-2.5-pro|flash|flash-lite`, `gemini-2.0-flash` (ước lượng, tier đắt); model lạ — kể cả tên deployment tuỳ ý — vẫn tính giá bảo thủ. Mẹo: đặt tên deployment Azure theo model (vd `gpt-4o`) để ước lượng đúng.
- **Che secret**: thêm `ya29.…` (Google access token), refresh token `1//…`, Entra client secret (`…8Q~…`); key Gemini `AIza…`, `sk-or-v1-…`, Azure `api-key`, SA JSON (`private_key`/`private_key_id`/email) đã có từ PR-0/PR-2. Hint của SA JSON là `json` (không lộ ký tự cuối file).
- Chưa làm (có chủ đích): Vertex bằng Workload Identity Federation (chỉ SA JSON), Azure Entra qua managed identity, kiểm tier trả phí của Gemini API (free tier có thể dùng dữ liệu để huấn luyện — admin nên đặt policy `allowed` theo provider), tile UI cho provider mới (PR-5).

### Added — AI PR-3b: backend cloud cho Co-work (A1, Refs #109)
- **`CloudToolBackend`** trên `LLMDriver` với tool-calling native (Anthropic / Bedrock / OpenAI-compatible): `find_files`, `list_dir`, `read_file`, `write_file`, `exec`; kết thúc bằng end-turn của model. Hết `409 AI_COWORKER_CLOUD_UNAVAILABLE`: route cloud (theo Settings › AI) giờ chạy thật; vẫn **không bao giờ** lặng lẽ chạy local thay cloud (và ngược lại).
- **Transcript phía server** (`agent_conversations.transcript`, append-only) + route ghim theo hội thoại (`route_kind/provider/model/ai_credential_id`, `owner_user_id`). Endpoint mới `POST /api/coworker/agent/conversations/{id}/step` nhận `{message}` | `{approve: pending_id}` | `{reject: pending_id}` | rỗng (tiếp tục); mọi trường khác (lịch sử, assistant/tool turn, `approved.args`, provider/route) bị bỏ qua. `GET …/conversations/{id}/route` (đọc-chỉ: chạy ở đâu và vì sao) và `GET …/route-preview`. Hội thoại của người khác = 404; hàng cũ (owner NULL) không step được.
- **Pending action do server giữ** (`agent_pending_actions`): id gắn với hội thoại + chủ; id lạ/của người khác/đã dùng → 409 `AI_PENDING_INVALID`; args thực thi luôn là args server đã lưu. `/step` stateless cũ chỉ còn cho backend local và cũng yêu cầu `pending_id` (web/agent.html đã cập nhật); với route cloud nó trả 409 `AI_COWORKER_USE_CONVERSATION_STEP` (lịch sử do client gửi không bao giờ lên cloud).
- **Điểm ra duy nhất `coworker_cloud_send()`**: che secret + PII (`scanner.cloud_ai.redact`) system prompt/skill và MỌI message trước khi chạm driver — bắt buộc, không phụ thuộc cờ privacy. Kết quả tool bọc `<workspace_data>` kèm lời nhắc "dữ liệu, không phải chỉ dẫn"; quét `injection_guard` → chú thích cho model + cờ UI; confirm `write_file`/`exec` kèm banner "đề xuất sau nội dung đáng ngờ" + host ngoài. Đường dẫn nhạy cảm (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.ssh/`, `.aws/`, `.git/config`, `.npmrc`, `.pypirc`, `*kubeconfig*`, `*.kdbx`…) trong route cloud → `awaiting_confirmation`, chưa gửi gì trước khi duyệt. Ảnh luôn do model vision LOCAL mô tả, chỉ text lên cloud (D15). `write_file` chứa marker che (`[REDACTED…]`, `[EMAIL]`, `[CCCD]`…) bị từ chối (D16).
- **Giới hạn**: trần observation, ngân sách upload 2 MB/hội thoại (`AI_UPLOAD_BUDGET`), trần 60 lần gọi model (`AI_STEP_CAP`), tin nhắn ≤ 20000 ký tự. Meter/quota/usage `feature='coworker'` như các call site khác; audit `vulnguard.audit.ai` (`coworker_call`, `coworker_action`) chỉ ghi id, không ghi nội dung.
- **Verify fixes (PR #118)**: (B1) `redact_egress()` thay `redact()` ở điểm ra: che `KEY=value`/`key: value` có/không nháy cho tên giống khoá (password/passwd/pwd/secret/token/api_key/access_key/private_key/client_secret/auth/cookie/session/webhook…), AWS secret key, `Authorization`/`Bearer`/`Basic`, `Cookie`/`Set-Cookie`, webhook Slack/Discord/Teams, URL có userinfo, `.netrc`/`.pgpass`, `curl -u/-b`, secret k8s, token có tiền tố (Stripe, npm, GitLab…), JWT/PEM; tái dùng `api.log_redaction.mask` (PR-2), xử lý từng dòng, regex tuyến tính, idempotent. (B2) coworker_host trả `resolved/symlink/hardlink` cho `/fs/file(_b64)`; cổng đường dẫn nhạy cảm xét đường dẫn yêu cầu VÀ đường dẫn thật (symlink/hard link/host cũ không báo meta ⇒ cần xác nhận, nội dung chưa lên cloud), danh sách mở rộng (`.kube`, `.docker/config.json`, `.git-credentials`, `.netrc`, `.pgpass`, keychain, profile trình duyệt, password manager, `*.tfstate`/`*.tfvars`, gcloud/azure/ssh/aws/gnupg, `.env*`…). (S1) approve trên cloud cần `ack` = `confirm_token` của đúng pending; pending rủi ro (đọc file nhạy cảm / sau nội dung đáng ngờ) cần thêm `explicit=true` và bị từ chối nếu `auto=true` (UI tự-duyệt không được bỏ qua — PR-5b phải ẩn nút này). (S2) pending hết hạn sau 15 phút (409 `AI_PENDING_EXPIRED`, hội thoại tự phục hồi). (S3) D16 áp cho cả `exec`. (S4) khoá hội thoại chỉ trong một process (đã ghi chú; launcher `--workers 1`, đa worker cần cột `version`/advisory lock).
- **Re-verify fixes (PR #118, vòng cuối)**: `redact_egress` thêm flag CLI (`--requirepass`, `--password=`, `-a` của redis-cli, `-pXXX` của mysql), `PGPASSWORD=`, URI MongoDB/`user:pw@` (che TRƯỚC luật PII), hash htpasswd/shadow (`$apr1$`, `$2y$`, `$6$`, `{SHA}`), cookie jar Netscape + `name<TAB>value` + cookie export JSON, `.netrc` nhiều dòng. Giảm che nhầm: từ khoá phải ở cuối tên khoá và bắt đầu một từ (không `bypass`), bỏ qua kiểu/annotation (`db: Session = Depends(..)`), lời gọi/thuộc tính/chỉ mục (`os.environ[..]`, `requests.Session()`), placeholder (`${VAR}`, `<token>`, `{tok}`), enum/nhãn trong code, chú thích; mã nguồn thật của repo đổi < 0,03% dòng (test chặn ngưỡng 0,1%). Dòng > 30 000 ký tự cắt tại khoảng trắng (không giữa `key=value`/nháy), khối đặc không phân cách bị che nguyên khối — an toàn với mọi giá trị `_LINE_CAP`. `coworker_host` không còn tác dụng phụ filesystem khi import: thư mục dữ liệu + token tạo lười khi host chạy (`startup`) hoặc khi cần (`get_token()`, `COWORKER_TOKEN` lười qua `__getattr__`).
- **Fix round cuối (PR #118)**: che `proxy_set_header X-Api-Key <v>` (hồi quy: trước đây dựa vào `log_redaction._BEARER` đã bỏ khỏi đường che; nay có luật header dấu cách riêng), `docker/podman login -p <pw>` (cùng `--password <pw>`/`--password=<pw>`), `.npmrc` `_password=`/`_auth=`/`:_authToken=` (luật "kiểu/annotation" chỉ áp cho `key: Type`, không cho `key=base64`; `//` chỉ là chú thích khi theo sau là khoảng trắng). IP nội bộ chỉ che khi là IPv4 RFC1918 đủ 4 octet (không che `10.0`, loopback, metadata). Che nhầm trên mã repo: 0,034% dòng (test chặn 0,1%, tính cả dòng IP).
- Migration idempotent: 6 cột `agent_conversations` + bảng `agent_pending_actions`. Skill-router `/route` luôn local.

### Added — AI PR-3: khoá AI theo từng user, policy, precedence, hạn mức, audit (Refs #109)
- **API user** `/api/me/ai-credentials` (list/create/PATCH/`PUT …/secret`/DELETE/`POST …/test` + `POST …/test` cho key chưa lưu): tạo = probe (PR-4) rồi mới lưu; không endpoint nào trả key/ciphertext; credential của người khác (kể cả ADMIN) = 404. VIEWER 403 (D10). User chỉ chọn provider `anthropic|bedrock|openai|openrouter`, không đặt được `base_url`/`aws_profile`; từ chối token OAuth `sk-ant-oat…`.
- **ADMIN**: `GET /api/ai/credentials` (metadata: chủ, provider, …4 ký tự cuối, trạng thái, lần dùng cuối, usage 30 ngày), `POST /api/ai/credentials/{id}/revoke`; không đọc/test/dùng key của user. `GET /api/ai/usage?scope=me|all&days=` (me: ANALYST+ADMIN; all: ADMIN). `GET/PUT /api/ai/settings` (policy chỉ ADMIN; `policy_public` cho mọi role). `GET /api/ai/models?credential_id=` cho chủ key.
- **Policy** (`ai_config.json › policy`): `byok allowed|required|off`, `fallback_to_org`, `allowed` (glob `provider:model`), `org_quota {usd_per_user_month, rpm_per_user}` (mặc định không giới hạn), `user_quota_own_keys.rpm_per_user` (120), `scheduled_jobs_credential org|owner|local_only`. Mặc định giữ nguyên hành vi cũ.
- **Precedence trong `resolve()`**: credential đã ghim → default của người khởi chạy → key org (nếu policy cho + còn hạn mức) → `Refuse(AI_NO_CREDENTIAL|AI_QUOTA|AI_NOT_ALLOWED|AI_CRED_REVOKED|AI_CRED_FORBIDDEN)`. Không bao giờ rơi sang key khác giữa job; key của user không phục vụ job hệ thống/lịch trừ policy `owner` + đúng chủ lịch; key admin không phục vụ người khác.
- **Ghim**: `scans.ai_credential_id` (+ `ai_sched_policy`/`ai_sched_owner_id` cho job lịch), `pentest_runs.ai_credential_id` (resume dùng lại đúng id; thu hồi/hết hạn mức giữa run → `PAUSED` + `AI_CRED_REVOKED|AI_QUOTA`, chủ re-pin bằng `PUT /api/pentest/runs/{id}/ai-credential` rồi resume từ checkpoint), `scan_schedules.created_by_user_id` + `ai_credential_policy`. Cột mới thêm bằng ALTER idempotent; id credential không xuất hiện trong API/báo cáo.
- **Usage + quota**: `Meter` gắn vào `LLMDriver.create` và `CloudAnalyzer`: kiểm credential/policy/rpm/quota TRƯỚC mỗi lần gọi, ghi `ai_usage_events` (credential_id + scope, không secret) SAU; giá ước lượng `api/services/ai_prices.py` (model lạ tính giá bảo thủ, không miễn phí). Purge usage 180 ngày, credential revoked/disabled 30 ngày.
- **Vòng đời user**: vô hiệu hoá / hạ VIEWER / xoá user → credential `disabled` ngay (xoá secret). Audit `vulnguard.audit.ai` ghi credential id + 4 ký tự cuối, không ghi key.
- **Co-work (A1)**: resolver định tuyến theo `mode` + `hybrid.tasks.coworker` (mặc định `local`); route ghim theo hội thoại (`pinned_route_kind`): local ghim vẫn local khi Settings sang cloud, cloud ghim bị `AI_ROUTE_CHANGED`/`AI_CRED_REVOKED`/`AI_QUOTA` (không đổi sang local/key khác); cloud cần model đã qua probe tool-calling (`AI_CLOUD_NO_TOOLS`). **Backend cloud là PR-3b**: tới lúc đó Co-work cloud bị từ chối (`AI_COWORKER_CLOUD_UNAVAILABLE`, HTTP 409), không bao giờ lặng lẽ chạy local thay.
- `RouteRefused` → HTTP 409 `{code, message_key}` toàn cục.
- **Verify fixes (PR #116)**: `PUT /api/scm/schedules/{id}` — chỉ người tạo lịch được đặt/giữ policy `owner` (ADMIN cũng không đặt cho người khác); lịch đang chạy bằng key cá nhân của người khác chỉ cho tắt / chuyển `org|local_only`. Job lịch dùng key cá nhân của chủ lịch bị rpm/quota theo chủ lịch. Meter tính giá + policy theo model hiệu lực (planner/executor/summarizer). Quota USD + rpm là reserve-then-settle nguyên tử trong DB (INSERT…SELECT có điều kiện; advisory lock trên Postgres) nên đúng cả khi song song/nhiều worker. Disable credential cùng transaction với vô hiệu hoá/hạ role/xoá user; resolver + Meter còn kiểm chủ `is_active`. `custom_base_url=off` áp cho cả `PUT /api/ai/config`. Re-verify: `update_schedule` kiểm policy MỚI sau khi resolve `inherit` (policy toàn cục `owner`), 403 nếu không phải chủ lịch; `scan_schedules.ai_owner_consent` — lịch bị người khác sửa không bao giờ chạy bằng key cá nhân của chủ lúc chạy (→ local) tới khi chủ lưu lại; chủ không tồn tại = fail closed; xoá lịch: chủ hoặc ADMIN; lưu lại đúng base_url cũ khi `custom_base_url=off` được phép. Ghim hội thoại Co-work (cột + wiring server) để PR-3b; test chặn client gửi route/credential.

### Added — AI PR-2: kho credential + mã hoá (Refs #109)
- Bảng `ai_credentials` / `ai_usage_events` (`api/ai_cred_models.py`) và kho `api/services/ai_credentials.py`: Fernet với sub-key riêng (`vulnguard-ai-cred:v1:` + secret key, `MultiFernet` để xoay khoá), envelope gắn chủ `{cid, owner, provider}` — ciphertext bị hoán đổi giữa hàng hoặc sai chủ bị từ chối. Không có getter plaintext: chỉ `open_for_call()` (giải mã đúng lúc → `ResolvedCredential`). Trạng thái `revoked`/`disabled` xoá secret ngay, purge sau 30 ngày.
- Startup migrate cấu hình AI của org (idempotent, cờ `migrations.creds_v1`, `org_credential_id`); `api_key_enc` cũ giữ nguyên một release để rollback; lỗi giữa chừng → rollback. Resolver vẫn org-only (không đổi hành vi); chưa có endpoint người dùng/policy (PR-3).
- Log: bộ lọc che key (`sk-ant-`, `sk-`, `sk-or-`, `ABSK`, `ksk_`, `AIza`, `ghp_`/`github_pat_`, Bearer, `x-api-key`, `?key=`) ở MỌI record, kể cả traceback; production từ chối khởi động nếu `ANTHROPIC_LOG`/`OPENAI_LOG=debug`. Mẫu che prompt thêm Azure 32-hex, Google service-account.

### Security — AI PR-4: probe kiểm tra key + SSRF guard (Refs #109)
- `api/services/url_guard.py`: base URL do ADMIN đặt (OpenAI-compatible, Ollama) được kiểm khi LƯU **và** ở mỗi request: chỉ https (Ollama: http chỉ tới local/LAN), cổng 443/11434/80 (+ `AI_URL_EXTRA_PORTS`), không userinfo/query/fragment, từ chối IP viết dạng thập phân/hex/bát phân/fullwidth, IPv6 nhúng IPv4 (`::ffff:`, NAT64, 6to4), link-local + metadata (`169.254/16`, `fd00:ec2::254`, `100.100.100.200`), loopback/RFC1918/CGNAT/ULA với cloud (trừ host trong `AI_BASE_URL_ALLOWLIST` — allowlist không bao giờ mở loopback/metadata). Resolve DNS phía server, mọi A/AAAA phải hợp lệ, **ghim IP** cho kết nối (chống DNS rebinding), không follow redirect, `trust_env=False`, giới hạn kích thước phản hồi.
- `POST /api/ai/test` nhận giá trị chưa lưu và trả `{ok, code, model, latency_ms, tools}` (`VALID|INVALID_KEY|NO_MODEL_ACCESS|RATE_LIMITED|NETWORK|TIMEOUT|BAD_BASE_URL|PROVIDER_ERROR|NO_CREDENTIAL`), không bao giờ trả văn bản của provider. Throttle 5 lần/phút/người dùng, 20/phút toàn cục (429).
- `POST /api/ai/ollama/check`: `/api/version`, `/api/tags`, probe tool-calling và JSON mode; cache 1 giờ theo (url, model).
- `GET /api/ai/models` lấy credential qua `llm_resolver` (không đọc key trực tiếp).
- **Thay đổi hành vi (đọc trước khi nâng cấp):** OpenAI-compatible `base_url` trỏ tới `http://` (LM Studio, vLLM, LiteLLM cục bộ…), IP nội bộ/loopback, hoặc cổng khác 443 giờ **bị từ chối** (lưu và lúc gọi). Cách giữ cấu hình cũ: đặt qua https và đưa host vào `AI_BASE_URL_ALLOWLIST` (mở dải private; loopback/metadata không bao giờ mở), cổng khác bằng `AI_URL_EXTRA_PORTS`. Ollama: LAN/loopback trên cổng 80/443 chỉ chấp nhận khi đó chính là host:port Ollama đã cấu hình (hoặc `AI_URL_EXTRA_PORTS`).
- Sửa sau verify: probe Anthropic/Bedrock dùng client `httpx2` của SDK 2.x (trước đó luôn trả `NETWORK`); `POST /api/ai/test` không dùng khoá đã lưu khi request đổi provider/base_url/region/auth_mode/profile (phải gửi `api_key` trong chính request); region Bedrock phải khớp `^[a-z]{2}(-[a-z]+)+-\d$` (lưu, test, lúc gọi); triage (`ai_analyzer`) và File Assistant (`ollama_client`) gọi Ollama qua `url_guard` ở mỗi request; mọi client SDK (Anthropic/Bedrock/OpenAI/OpenRouter) không đọc proxy env và không follow redirect.

### Changed — AI PR-1: LLM resolver seam (không đổi hành vi, Refs #109)
- Mọi lời gọi LLM (triage, reanalyze, `/api/ai/test`, Pentest, Document Review, Co-work, File Assistant) đi qua `api/services/llm_resolver.py`: `resolve(LLMContext) → Route` (`LocalOllama` | `Cloud(ResolvedCredential)` | `Refuse`). Vẫn chỉ cấu hình org; định tuyến theo `mode` y như trước. Client SDK chỉ dựng ở `open_client()` (`build_client` bị gỡ khỏi `cloud_ai`).
- `ResolvedCredential` che trong repr, không pickle/copy/JSON được; `cfg` của Pentest chỉ mang route + ctx (không secret). `make_driver(route)`; Ollama là route native cho agent (`{url}/v1`, không cần key).
- Co-work: `CoworkBackend`/`LocalJsonBackend` (giao thức JSON-in-text giữ nguyên), luôn `LocalOllama`. Hội thoại Co-work có `owner_user_id` và list/get/delete theo chủ sở hữu (hàng cũ chỉ ADMIN thấy).
- Cột mới: `pentest_runs.started_by_user_id` (migration `m0013`, backfill theo email), `scans.triggered_by_user_id`, `agent_conversations.owner_user_id`.

### Security — AI PR-0: rò rỉ khoá AI + sửa lỗi Ollama URL (Refs #109)
- Bedrock API key không còn ghi vào `os.environ`; truyền theo từng client. Tiến trình con của scanner/pentest (`spawn`, `run_command`, katana) loại `AWS_*`, `ANTHROPIC_*`, `OPENAI_*`, `OPENROUTER_*`, `KIRO_*`, `AZURE_OPENAI_*`, `GOOGLE_*` (env tường minh của caller vẫn được tôn trọng).
- Lỗi provider không còn trả nguyên văn: `/api/ai/test` và `run.error_message` dùng mã chuẩn hoá + chi tiết đã che. Thêm mẫu che `ABSK…`, `ksk_…`, `sk-or-v1-…`, Bearer/query token.
- Co-work, Document Review, File Assistant dùng Ollama URL cấu hình trong UI. Thẻ trạng thái báo "model đã cấu hình chưa cài" thay vì lặng lẽ đổi model.
- Sửa nhãn sai "kiro-cli login tạo AWS profile" (UI + docs).
- Verify round 3: allowlist env giữ cấu hình tool tài liệu hoá (`SEMGREP_HOME`, `TRIVY_*`, `GRYPE_*`, `NUCLEI_*`, `CHECKOV_*`…) nhưng vẫn loại tên chứa TOKEN/SECRET/PASSWORD/KEY/CREDENTIAL; lỗi LLM trong vòng lặp pentest giờ được commit (run FAILED + error_message đã sanitise) thay vì bị `db.refresh` huỷ.
- Verify round 2: lỗi LLM trong vòng lặp pentest, ai_analyzer, scans, domains đều qua `sanitize_error`; log chỉ ghi bản đã che. Env tiến trình con (spawn/run_command/git clone/tool check/which) là ALLOWLIST — `GITHUB_TOKEN`, `DATABASE_URL`, `*_TOKEN/_SECRET/_KEY` không bao giờ lọt; `spawn(env=…)` thay thế thay vì trộn.

### Changed — PDF PR-5: mailer + dọn dẹp fpdf2 (closes #102)
- Email báo cáo định kỳ đính kèm PDF do engine Typst dựng (cùng builder với nút tải); engine lỗi/bận → gửi email không đính kèm, ghi log. Việc dựng PDF chạy trong thread, không chặn event loop.
- Gỡ `fpdf2`/`Pillow`/`fonttools` khỏi lockfile, `report_builder.build_pdf`, `pentest.report.to_pdf/pdf_lines`, font DejaVu cũ (`scanner/assets/fonts`) và bước cài `fonts-dejavu` trong Dockerfile.
- Trường văn bản tự do (description/remediation/matched_at/vị trí) được che secret (cùng redactor) và cắt độ dài **trước** khi dàn trang.
- Job PDF: mỗi worker/instance dùng thư mục con riêng; sweeper không còn xoá file của worker khác. `filename*` quá dài giữ lại đuôi `_YYYYMMDD`.
- `/export?format=pdf` bỏ qua bộ lọc severity/status/scan_type/diff/scope (có tài liệu + header `X-VG-Filters-Ignored`).

### Added — PDF PR-3: tải PDF trực tiếp (Typst)
- `format=pdf` cho scan / pentest / web scan / doc review dựng bằng engine Typst và trả file đính kèm (tên file an toàn + `filename*` RFC 5987); job nền `POST|GET /api/reports/pdf-jobs` cho báo cáo > 300 phát hiện; `503 pdf_busy` + `Retry-After`; rate-limit + audit log.
- UI: một nút "⬇ Xuất PDF" tải file; gỡ `window.print`, nút "In/Lưu PDF", "PDF nhanh" và ghi chú Ctrl/Cmd+P.

### Security — Docker hardening, supply chain, lockfiles (PR-H; N-5, N-9, L-5, B-6) (BREAKING for local-image scans / dependency workflow)
- **N-5 / D-4:** `docker.sock` is no longer mounted into the app (a `:ro` socket mount still accepts `POST /containers/create` with `Privileged`).
  New `docker-compose.local-images.yml` routes `DOCKER_HOST` through a pinned, read-only `docker-socket-proxy` (`POST=0`, images/ping/version only; port not published).
  **Breaking:** scanning images that exist only in the local daemon now requires `-f docker-compose.local-images.yml`; public images are unaffected.
- **N-9:** compose hint is now `sudo chown -R 10001:10001 storage` (no `chmod 777`); new `api/docker-entrypoint.sh` fails fast with that hint when `/app/storage/db` is not writable.
- **L-5:** every downloaded binary (trivy, gitleaks, grype, hadolint, katana, nuclei, ffuf, sonar-scanner) is version-pinned and verified with per-arch `sha256`;
  no more `curl | sh` for grype; trivy comes from the release tarball (not the unpinned apt repo); SecLists pinned to a tag.
  Core scanners (trivy, gitleaks, grype, hadolint) now fail the image build on any error; only optional tools may be skipped.
- **B-6:** `api/requirements.in` → hash-locked `api/requirements.txt` (`uv pip compile --universal --generate-hashes`), installed once with `--require-hashes`.
  semgrep, bandit, checkov, pip-audit each get their own venv from `docker/scanners/<tool>.txt`; `detect-secrets` stays in the app env. `requirements-dev.txt` and `coworker_host/requirements.txt` are locked too.
  CI installs from the lock and runs `pip-audit` on it; `.github/dependabot.yml` added. Image smoke test now also runs `grype`, `hadolint` and `pip check`.
- Review follow-ups: `FORWARDED_ALLOW_IPS` is now passed through `docker-compose.yml` (`.env` setting works); `defusedxml` added to `requirements.in` + lock (PR #43 should drop its raw `requirements.txt` line); entrypoint also detects root-owned files inside storage (e.g. `db/vulnguard.db`) and derives the path from `DATABASE_URL`; `install/install.sh` installs semgrep/bandit/checkov/pip-audit into separate venvs from `docker/scanners/*.txt` (no more co-install into the app venv).
- Image: `FORWARDED_ALLOW_IPS=127.0.0.1` made explicit, uvicorn started with `--workers 1` (in-memory state; run.sh single-worker enforcement is in PR #42).

### Security — low-severity hardening (PR-I: L-6, B-5; L-4 is delivered by #37)
- Qualys/OpenVAS connectors parse XML with `defusedxml` (billion-laughs / entity expansion is rejected and the
  parser returns no results; Bandit B314 ×4 gone). `defusedxml` is pinned in `api/requirements.in` + the hash lock (PR-H).
- **BREAKING:** VulnGuard supports a single worker. `run.sh`, `install/run.sh` and the systemd unit force `--workers 1`;
  `VULNGUARD_WORKERS>1` is ignored with a warning (in-memory scan locks, proxy registry, scheduler, lockout, Co-work nonces).
- **BREAKING:** native `scripts/setup.py` now binds `VULNGUARD_BIND` (default `127.0.0.1`, was `0.0.0.0`); the systemd
  template binds `127.0.0.1`. `run.sh`/`setup.py`/`install/run.sh` refuse to start with `AUTH_ENABLED=false` and a non-loopback host.
- **LAN access (opt-in, documented):** one variable `VULNGUARD_BIND` (default `127.0.0.1`) now controls the bind for Docker compose
  *and* native `run.sh`/`run.ps1`/`install/run.sh`/`setup.py`; `VULNGUARD_HOST` stays as a deprecated alias (warning). The app and every
  launcher refuse to start on a non-loopback bind with `AUTH_ENABLED=false`. Startup logs warn on LAN bind without `ALLOWED_HOSTS` /
  with plain-HTTP cookies. The pentest MITM proxy port has its own `PENTEST_PROXY_BIND` (default loopback) so opening the UI does not
  expose it; optional `docker-compose.lan.yml`. Compose now passes `AUTH_ENABLED`, `ALLOWED_HOSTS`, `COOKIE_SECURE`, `CORS_ALLOW_ORIGINS`,
  `VULNGUARD_SECRET_KEY`, `SESSION_TTL_HOURS`, `EXPOSE_API_DOCS`, `SCM_*` into the container (previously `.env` had no effect there).
  `run_demo.sh` now binds loopback by default. New wiki page "Truy cập từ máy khác trong LAN" (incl. Caddy TLS), fixes wrong Installation.md.
  The "anyone on the LAN can claim ADMIN via `/api/auth/setup`" gap is closed by the setup token in #42 (not duplicated here).
- Skipped on purpose: L-4 (pentest proxy auth, loopback default, CA lifetime) — already implemented in #37.

### Security — first-run setup token (L-2, BREAKING first-run UX) + single worker (D-14)
- `POST /api/auth/setup` now requires `setup_token`: `VULNGUARD_SETUP_TOKEN`, or an auto-generated `storage/setup_token`
  (0600, created only while no user exists, deleted after a successful setup; never logged — only its path). Wrong/missing
  token → 403, repeated guesses → 429 (shared lockout limiter). `/api/auth/status` adds `setup_token_required`.
- Hardening after review: the token file is created at startup (stale file removed when users exist); setup is atomic (single winner, others 409); a correct token is never rate-limited and wrong guesses share one global bucket (no per-IP/X-Forwarded-For dependence, so NAT/LAN attackers cannot lock the owner out); env tokens shorter than 16 chars are ignored; `docker-compose.yml` forwards `VULNGUARD_SETUP_TOKEN`.
- Setup is guarded at DB level (single-row `setup_state` PK in the same transaction as the first ADMIN), so it holds across processes; a laggard request never regenerates the token file (only startup creates it); `--workers 1` is explicit in the Dockerfile CMD, systemd template, `install/run.sh` and `scripts/setup.py`. Custom env tokens must be random >=128-bit (the limiter does not slow guessing).
- Login page setup form has a "Setup token" field. `scripts/bootstrap_admin.py` (installer) is unchanged.
- `run.sh` ignores `VULNGUARD_WORKERS>1` with a warning (in-memory state requires a single worker).
- Tests: `tests/test_setup_token.py`.

### Fixed — first-login change-password UX (BREAKING for API clients)
- `POST /api/auth/change-password` now requires `confirm_password` (must equal `new_password`, else 422, nothing written)
  and enforces a password policy (10–200 chars, ≥3 of 4 character classes, not containing the email local part,
  not a single repeated character). The same policy applies to `/setup`, `POST /users` and `PATCH /users/{id}`.
- After a change the response returns a fresh session; all other sessions/tokens are revoked (`token_version`). Failed-login
  lockout for the account is cleared.
- Web UI: forced-change dialog has new + confirm fields, strength meter, rule text, show/hide; reloads after success so the
  stale "must change password" errors disappear.
- Tests: `tests/test_change_password.py` (API) and `tests/test_ui_change_password.py` (headless Chromium, runs in CI).


### Security — path allow-lists, zip bomb, File Assistant (fix/path-policy)
- **M-3** `scan_path` must resolve (realpath, so symlinks and `..` cannot escape) under an allowed root for every role. New `api/services/path_policy.py`; roots from `SCAN_ALLOWED_ROOTS`, default `/workspace` (Docker) or the user's home (native), plus `storage/scan_uploads`. The app storage directory (DB, `secret.key`) is always refused. Violations return 400.
- **H-1** File Assistant file paths are validated against `FILE_ASSISTANT_ALLOWED_ROOTS` (default: scan roots) at session creation (client `size_bytes` is ignored, max 20 MiB) and re-validated before every read, so legacy sessions or swapped symlinks are rejected.
- **M-5** Zip uploads are streamed to a temp file (413 above `UPLOAD_MAX_BYTES`) and extracted with limits on file count, total uncompressed size, compression ratio and actual bytes written per member (lying headers abort), plus a free-disk check. Failed extractions are removed; rotating out an old upload scan deletes its directory.
- **B-4** File Assistant health uses `text("SELECT 1")` (database check was always false) and really probes the Coworker Host.

### PR #32 verification fixes
- Deny-list (app storage, credential dirs) is compared casefold + NFC on both the raw and resolved path, so `STORAGE`/`.DOCKER` on case-insensitive APFS no longer bypass it.
- Credential deny-list for scan and File Assistant: `~/.ssh`, `.gnupg`, `.aws`, `.azure`, `.config`, `.docker`, `.kube`, `.local`, `Library`, `.netrc`, `.npmrc`, `.pypirc`, git credentials; files `.env*`, `*.pem`, `*.key`, `*.p12`, keychains, `id_*`, the app `.env`. Scanning a directory that contains such a folder (e.g. `~` itself) is refused: pick the project folder.
- `storage/scan_uploads` is no longer a selectable root (cross-project read); rotation only deletes `scan_uploads/<own project>/<hex>`, never a RUNNING scan or a path another scan still references.
- Relative `scan_path` is rejected; relative or missing configured roots are ignored with a warning.
- Zip: End-of-Central-Directory entry count / size is checked before `zipfile` parses the directory; `Content-Length` (or streamed bytes) over `UPLOAD_MAX_BYTES` + 1 MiB is rejected with 413 by a middleware before Starlette spools the body.
- File Assistant re-checks the file extension on the resolved path.

### PR #32 re-verification fixes
- Credential deny-list is now a blanket rule: every top-level dot entry under `$HOME` (`~/.*`, casefold + NFC) plus `~/Library` is refused for both scan and File Assistant, and `~` itself (or an ancestor) cannot be scanned. A project placed under a dot directory of home (or `SCAN_ALLOWED_ROOTS` pointing into one) is therefore refused too. macOS firmlink aliases (`/System/Volumes/Data/...`) are normalised.
- Zip pre-check no longer trusts EOCD counts: it locates the central directory the way CPython does (always probing the Zip64 locator) and counts records without building `ZipInfo`, aborting past `UPLOAD_MAX_FILES`.
- A chunked upload over the limit now returns a real 413. Every POST/PUT/PATCH body is bounded (`BODY_MAX_BYTES`, default 300 MiB; `/scan-upload` uses `UPLOAD_MAX_BYTES`).

### Breaking changes (path-policy)
- Scanning `~` itself, or any directory containing a credential folder, is refused in native mode.
- **D-7** Scans of paths outside the allowed roots are now refused (400), for all roles. Set `SCAN_ALLOWED_ROOTS` to widen. Existing scans are unaffected.
- **D-8** `FEATURE_FILE_ASSISTANT` now defaults to `false` (module returns 404) until its UI exists; set it to `true` to use the API.
- Known residual: a directory swapped for a symlink between validation and scan (TOCTOU) is not prevented.

### Security — Coworker Host exec policy (BREAKING)
- `COWORKER_EXEC_MODE` (`safe` default / `trusted` / `off`). In `safe`, Co-work can no longer run
  `python3`, `pytest`, `npm`, `make`, `go`, `cargo`... Set `COWORKER_EXEC_MODE=trusted` on the host to opt in
  (each non-read command then needs a server-issued, single-use `confirm_id`; the old `confirm: true` flag is ignored).
- Command arguments are confined to the granted folder; `find -exec`, `grep -R`, `tail -f`, `git -c ...` etc. are rejected.
  Only bare command names are accepted (no `./cat`, `/bin/cat`).
- `PUT /whitelist` only accepts read-only commands; stored whitelists are intersected with them.
- Folder grants for `~/.ssh`, `~/Library`, `/etc`, ancestors of `$HOME`, or the coworker data dir are refused
  (also enforced at use time for existing grants). Optional `COWORKER_ALLOWED_ROOTS`.
- Writes into `.git/.husky/.vscode/.idea/.direnv/.envrc` and the coworker data dir are refused.
- Host header parsing handles IPv6 (`[::1]:8765`); an empty Host is rejected (421).
- The auto-generated token is no longer logged (only its file path). `coworker_host/run.sh` no longer sources `.env`.
- Scanner subprocesses no longer inherit `VULNGUARD_COWORKER_TOKEN`, API keys or cloud secrets.
- Hardening after independent adversarial review: all path policies (folder grants, write denylist, DATA_DIR,
  `COWORKER_ALLOWED_ROOTS`) compare case-insensitively (`~/.SSH`, `/USERS/x`, `.GIT/config` on APFS/NTFS);
  git runs with `--attr-source=<empty tree>` (needs git >= 2.40) so `filter`/`textconv` drivers from `.gitattributes`
  cannot execute; safe-mode `git branch` is list-only; `git blame --contents`, `--no-index`, `--ignore-revs-file`,
  `-O` are denied and every git path-like value is confined; `find` global flags (`-H -L -f -P -x ...`) are parsed
  before confinement; `grep`/`tail`/`tree`/`ls` short-option clusters (`-rf`, `-fPATH`, `-rS`, `-lH`) are parsed
  getopt-style; writes to `.gitattributes`/`.gitmodules` are refused; child stdin is `/dev/null`; bracketed Host
  headers must be well-formed (`[::1]evil` -> 421).
- Second review round: git runs with `GIT_CEILING_DIRECTORIES=<parent of root>` and a pre-flight that refuses (403)
  when the repo's toplevel / git-dir / common-dir resolve outside the granted root (dotfiles repo at `$HOME`,
  `.git` file with `gitdir:` outside, `core.worktree` outside; legitimate `git worktree` checkouts whose gitdir is
  outside the root are therefore refused) or when `.git/info/attributes` defines attributes (hostile-repo filter/textconv).
  `find` parses BSD flag clusters (`-xL`, `-Ef`, `-sx`) and `--`; `diff -r/--recursive` is denied (Apple diff follows
  symlinks while recursing) and attached `-X<file>` is confined; Host ports must be numeric.
- Third review round: `find -f<path>` (attached value) denied; `diff` operands must not be directories (Apple diff follows
  symlinked entries one level down); safe-mode `git diff`/`git status` run with `--ignore-submodules=all`
  (+ `diff.submodule=short`, `status.submoduleSummary=false`) and `--submodule*`/`--ignore-submodules*` are denied, so a hostile
  submodule gitdir cannot run its filters (side effect: dirty submodules are not shown); repos whose
  `objects/info/alternates` point outside the granted root are refused. Linked `git worktree` checkouts with the gitdir
  outside the root remain unsupported (fail-closed).

### Security — auth-off, CORS/CSRF, RBAC, docs, headers (fix/authoff-cors-rbac)
- **M-2** `AUTH_ENABLED=false` no longer exposes admin power: admin-only routes, `/api/coworker` and `/api/file-assistant` return 403 (`auth_required`); the dev pseudo-user is ANALYST; Host must be loopback (or `ALLOWED_HOSTS`) → 421 (DNS rebinding); the File Assistant WebSocket refuses when auth is off. CORS `*` removed (same-origin only unless `CORS_ALLOW_ORIGINS`). New Origin/`Sec-Fetch-Site` guard rejects cross-site writes (`bad_origin`) with auth on or off.
- **L-1** `ADMIN_ONLY` now covers `POST/DELETE /api/settings/*` (logo, SonarQube/SMTP test), `POST/DELETE /api/scm/connections`, `GET /api/scm/connections/{id}/…`, `POST /api/ai/test`. SCM `base_url` is SSRF-checked (https only, no loopback/link-local/metadata; private ranges allowed by default) at create, validate, list and clone time.
- **L-3 / D-11** `must_change_password` is enforced by the API (403 `must_change_password`), not only the UI; users created by an admin and admin password resets set the flag. Fixed a latent bug where `POST /api/auth/change-password` modified a detached user object and never persisted.
- **I-1** `/docs`, `/redoc`, `/openapi.json` require login; `EXPOSE_API_DOCS=false` disables them. `mask_secret` shows only `…` + last 4 chars.
- **E.5** Security headers on every response (`nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`) and a baseline CSP on HTML pages (Google Fonts allowed for `brand.css`).

#### Review follow-ups (PR-E)
- VIEWER accounts forced to change their password can now call `change-password`, `logout` and `logout-all` (previously permanently locked out).
- `must_change_password` is also enforced on the File Assistant WebSocket.
- `POST /api/auth/setup` returns 403 when `AUTH_ENABLED=false` (cannot plant the first ADMIN).
- SCM `git clone` no longer follows HTTP redirects and only allows https (http with `SCM_ALLOW_HTTP`).
- `check_base_url`: blocks `100.100.100.200`, `192.0.0.192`, IPv6-embedded IPv4 (6to4/NAT64/Teredo); with `SCM_ALLOW_PRIVATE_HOSTS=false` requires a globally routable address.

#### Breaking changes (PR-E)
- Third-party browser clients of the API break unless listed in `CORS_ALLOW_ORIGINS`. The bundled UI is unaffected.
- With `AUTH_ENABLED=false`, Co-work, File Assistant and all admin routes are unavailable; requests with a non-loopback `Host` get 421.
- Newly created users and admin-reset passwords must change the password before using the API.
- `/docs`, `/redoc`, `/openapi.json` need a session; masked key hints now show only the last 4 characters.
- ANALYST/VIEWER can no longer call the SCM connection management, settings sub-endpoints or `/api/ai/test`.

### Security — session revocation (fix/session-revocation)
- **N-1** `POST /api/auth/logout` now actually revokes the JWT (per-token `jti` denylist, table `revoked_tokens`, created automatically). Previously the endpoint was public, the revoke branch never ran and the token stayed valid for `SESSION_TTL_HOURS`.
- **N-2/M-4** File Assistant WebSocket validates the real session (revocation, `token_version`, `is_active`, current role) before `accept()` and on every message; rejects cross-origin handshakes and honours `FEATURE_FILE_ASSISTANT`.
- **N-3** Login lockout no longer locks out the legitimate user: buckets by a signed per-device cookie (`vg_device`) when present, otherwise one shared untrusted bucket per email; bounded store; `Retry-After` header.

### Hardening after independent verification
- Device cookie MAC is now unambiguous (length-prefixed, derived subkey, bound to the user id, strict nonce format); an email containing `|` can no longer mint trusted buckets for another account.
- Lockout check + attempt increment is atomic and happens before the scrypt verification, so concurrent guesses cannot exceed 5.
- Untrusted clients share one bucket per email (not per IP); locked buckets are not evicted when the store is full.
- Unknown-email logins verify against a precomputed dummy hash (equal timing); logout falls back to the cookie token when the `Authorization` header token is invalid.

### Breaking changes
- Rotating `VULNGUARD_SECRET_KEY` invalidates all `vg_device` cookies. Clients without the cookie (CLI/CI) can still be locked for 15 minutes by anyone who can reach the login endpoint.
- Logout now revokes **only the current token** (decision D-1). Other sessions / CLI tokens of the same user keep working. Use the new `POST /api/auth/logout-all` to end every session of a user.
- JWTs now carry a `jti` claim. Tokens issued before this release (no `jti`) are revoked on logout by bumping `token_version`, which ends all sessions of that user.
- WebSocket clients sending an `Origin` that differs from `Host` are refused.
