# Settings › AI — web ↔ API contract (PR-5, refs #109)

> Source of truth: the backend routes (`api/routes/ai_settings.py`, `ai.py`, `ai_credentials.py`, `ollama.py`) and plan §6/§4.11.
> The page (`web/ai-settings.js`) talks only to these real endpoints. There is no bridge/mock mode and no feature flag; the two legacy tabs (Ollama & Model, AI Provider) are removed.

| Endpoint | Role | Shape used by the UI |
|---|---|---|
| `GET /api/ai/settings` | any | `public_config()` (`mode, provider`, sections `anthropic, bedrock, openai, openrouter, azure_openai, gemini, vertex, openai_compatible` with `api_key_set, api_key_hint`; `hybrid{escalate_min_severity,fp_band_low,fp_band_high,tasks{coworker}}`, `privacy`) + `ollama{url,custom,default_url,model,vision_model}`, `providers_available[]`, `policy_public{byok,allowed,fallback_to_org,usd_per_user_month}`, `status{cloud{provider,configured},mine{source:own\|org\|none,provider,hint}}`. ADMIN only: `policy{byok,fallback_to_org,allowed,org_quota{usd_per_user_month,rpm_per_user},scheduled_jobs_credential,custom_base_url,azure_deployment_models{"<resource>/<deployment>":model}}`, `advanced.pentest_models` (read-only, env-driven). |
| `PUT /api/ai/settings` | ADMIN | same shape; keys only via `<section>.api_key` (write-only) or `<section>.clear_api_key`; `ollama{url,model,vision_model}`; `policy` (`azure_deployment_models` is REPLACE). `advanced` is ignored. 422 `detail` is a string `CODE: text` — the UI uses only `CODE`. |
| `POST /api/ai/test` | ADMIN | body = unsaved values of the selected provider (`provider, model, base_url, auth_mode, region, aws_profile, endpoint, deployment, api_version, tenant_id, client_id, project, location, api_key`); resp `{ok, code, provider, model, latency_ms, tools, json}`. Rendered from `code` only. |
| `POST /api/ai/ollama/check` | ADMIN | body `{url?, model?, force?}`; resp `{ok, code, version, model_installed, tools, json, latency_ms}` |
| `GET /api/ollama/models`, `/health`, `POST /pull`, `DELETE /models/{name}` | read: any; write: ADMIN | installed models / pull / delete (installed list + reachability for the page) |
| `GET /api/ai/models?provider=` | ADMIN | model suggestions (`{models, source}`) |
| `GET/POST /api/me/ai-credentials` | ANALYST, ADMIN | list `{credentials[{id,provider,label,key_hint,model,region,deployment,endpoint,api_version,status,last_validated_at,last_error_code,is_default}],policy}`; create `{provider,secret,model?,label?,region?,resource?,deployment?,api_version?,is_default}` — providers `anthropic,bedrock,openai,openrouter,azure_openai,gemini`; Azure = resource name + deployment only |
| `PATCH` / `PUT …/{id}/secret` / `DELETE` / `POST …/{id}/test` | owner | `{is_default,…}` / `{secret}` (validated before swap) / 204 / `{ok,code,model,latency_ms,tools}` |
| `GET /api/ai/credentials`, `POST …/{id}/revoke` | ADMIN | `{credentials[{id,owner{id,email},provider,label,key_hint,status,last_used_at,calls_30d,est_cost_usd_30d}]}`; metadata only |
| `GET /api/ai/usage?scope=all&days=30` | ADMIN | `{rows[{user_email,credential_scope:user\|org\|system,provider,key_hint,calls,est_cost_usd,quota_pct?}]}` |

Errors: HTTP 429 → "too many attempts"; otherwise the normalised code (`detail.code`, `code`, `[code]` prefix or `CODE:` prefix of a string `detail`) is mapped to `code.*` i18n strings; anything unknown → generic message. Provider/server text is never rendered.
Secrets: sent once in a request body; inputs are `type=password` (Vertex SA JSON too), cleared right after a save/create/rotate, never in JS state, storage, URL, toasts.
Not provided by the backend (so not in the UI): last-scan escalation preview, org-key "saved by/at", per-role Pentest model editing (env only).
Co-work: `hybrid.tasks.coworker: "local"|"cloud"` (default `local`), ADMIN only; no picker inside Co-work.
