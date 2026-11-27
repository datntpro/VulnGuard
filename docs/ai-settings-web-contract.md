# Settings › AI — web ↔ API contract (PR-5, refs #109)

The page (`web/ai-settings.js`) probes `GET /api/ai/settings`. 200 → **contract** mode (below). 404/405/501 → **bridge** mode:
sections 1–3 are assembled from `/api/ai/config` + `/api/ollama/*`; sections 4–5, testing unsaved values and the tool-calling
check show "not available yet" (never a fake success) and the two legacy tabs stay reachable. Endpoints are exactly those of §6 of the plan;
the *shapes* below are what the UI expects (PR-3/PR-4 must match or update this file + `tests/test_ui_ai_settings.py`).

| Endpoint | Shape used by the UI |
|---|---|
| `GET /api/ai/settings` | `public_config()` fields (`mode, provider, anthropic, bedrock, openai, openrouter, hybrid, privacy`; sections carry `api_key_set, api_key_hint, api_key_saved_by?, api_key_saved_at?`) plus `ollama{url,custom,default_url,model,vision_model,reachable,latency_ms,version,installed[{name,size_gb,tools:bool\|null}],check?}`, `providers_available[]`, `preview{items:[[severity,fp%\|null]]}` (counted server-side from the last scan, no LLM call), `policy_public{byok,allowed[],fallback_to_org,usd_per_user_month}` (all roles), `policy` + `advanced.pentest_models` (ADMIN only), `status{ollama{reachable,latency_ms,model,tools},cloud{provider,configured,last_test_at,last_test_ok},mine{source:own\|org\|none,provider,hint}}` |
| `PUT /api/ai/settings` (ADMIN) | same body as today's `PUT /api/ai/config` + `ollama{url,model,vision_model}`, `advanced`, `policy`; keys only when typed (`<section>.api_key`) or `<section>.clear_api_key` |
| `POST /api/ai/test` (ADMIN) | body = unsaved form (same shape as PUT); resp `{ok,provider,model,latency_ms,tools,json,code}`; `code` ∈ VALID, INVALID_KEY, NO_MODEL_ACCESS, RATE_LIMITED, NETWORK, TIMEOUT, BAD_BASE_URL. Provider text is never displayed |
| `POST /api/ai/ollama/check` (ADMIN) | body `{url?,model?}`; resp `{ok,code?,latency_ms,version,model_loaded,tools:bool\|null,json_ok,json_total}` |
| `GET/POST /api/me/ai-credentials` | list `{credentials:[{id,provider,label,key_hint,model,region,status,last_validated_at,is_default}]}`; create body `{provider,model,label,region?,secret,is_default}` |
| `PATCH` / `PUT …/{id}/secret` / `DELETE` / `POST …/{id}/test` | `{is_default}` / `{secret}` / – / `{ok,code,model,latency_ms,tools}` |
| `GET /api/ai/credentials` (ADMIN) | `{credentials:[{id,owner{email},provider,key_hint,status,last_used_at}]}`; `POST …/{id}/revoke` |
| `GET /api/ai/usage?scope=all&days=30` (ADMIN) | `{rows:[{user_email,credential_scope:user\|org\|system,provider,key_hint,calls,est_cost_usd,quota_pct?}]}` |

Secrets: the UI sends a key once in a request body, clears the input immediately, keeps nothing in JS state/localStorage, and never prints server text (only normalised `code`s; legacy `error` strings are masked and truncated).
