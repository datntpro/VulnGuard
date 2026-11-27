"""E2E (Chromium headless): Settings › AI hợp nhất (PR-5, refs #109) chạy trên BACKEND THẬT (PR-3 / PR-3b / PR-4 / PR-6).

Không còn mock hợp đồng: trình duyệt nói chuyện với app FastAPI thật (đăng nhập, role, /api/ai/settings, /api/me/ai-credentials,
/api/ai/credentials, /api/ai/usage, /api/ollama/*). Chỉ có HAI thứ được thay thế ở biên ngoài của hệ thống:
  • provider cloud: `api.services.ai_probe.probe_cloud` (không có mạng ra Internet trong CI) → kết quả điều khiển được;
  • Ollama: một server HTTP giả trên 127.0.0.1 (url_guard cho phép loopback với Ollama) — nên `/api/ollama/*` và
    `POST /api/ai/ollama/check` chạy mã thật.
Riêng test "never render server text" chặn vài response bằng page.route() để bơm text độc hại — đó là mục đích của test.

Ảnh chụp (light/dark, VI/EN, 3 role, 390 px) ghi ra thư mục AI_UI_SHOTS nếu biến môi trường này được đặt.
"""
import http.server
import json
import os
import socket
import threading
import time

import pytest

pw_sync = pytest.importorskip("playwright.sync_api")

import uvicorn

from api.ai_cred_models import AiCredential, AiUsageEvent
from api.auth_models import UserRole
from api.database import SessionLocal
from api.main import app
from tests._authutil import PASSWORD, make_user

SECRET = "sk-ant-api03-SUPERSECRETVALUE-0123456789abcdef"
SECRET2 = "ABSKQmVkcm9ja0FQSUtleS1TRUNSRVQtMDEyMzQ1Njc4OQ=="
SECRET3 = "sk-ant-api03-ANALYSTSECRETKEY-9988"
SECRET4 = "sk-ant-api03-ROTATEDSECRETKEY-7766"
AZKEY = "0123456789abcdef0123456789abcdef"
SA_JSON = json.dumps({"type": "service_account", "project_id": "my-gcp-proj-1", "private_key_id": "k1", "client_email": "svc@p1.iam.gserviceaccount.com",
                      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIBVQSECRETSAKEY\n-----END PRIVATE KEY-----\n"}, indent=2)
SHOTS = os.environ.get("AI_UI_SHOTS")


# ───────── hạ tầng: app thật + Ollama giả + probe cloud giả ─────────
class _Ollama(http.server.BaseHTTPRequestHandler):
    models = {"qwen2.5:7b": True, "llama3.2": True, "deepseek-coder:6.7b": False}    # tên → hỗ trợ tool-calling

    def log_message(self, *a):
        pass

    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/version":
            return self._send({"version": "0.12.3"})
        if self.path == "/api/tags":
            return self._send({"models": [{"name": n, "size": int(4.7e9), "modified_at": "2026-11-01T00:00:00Z"} for n in self.models]})
        self.send_response(404); self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/api/chat":
            if body.get("tools"):
                if self.models.get(body.get("model")):
                    return self._send({"message": {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "get_weather", "arguments": {"city": "Hanoi"}}}]}})
                return self._send({"message": {"role": "assistant", "content": "I cannot call tools"}})
            return self._send({"message": {"role": "assistant", "content": '{"ok": true}'}})
        self.send_response(404); self.end_headers()


PROBE = {"code": "VALID", "tools": True, "latency_ms": 640}      # điều khiển bởi test
PROBE_CALLS = []                                                   # (provider, model) mỗi lần probe


@pytest.fixture(scope="module")
def base_url():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True); t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=5)


@pytest.fixture(scope="module")
def fake_ollama():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Ollama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module", autouse=True)
def env(tmp_path_factory, fake_ollama):
    mp = pytest.MonkeyPatch()
    d = tmp_path_factory.mktemp("aiui")
    mp.setenv("AI_CONFIG_FILE", str(d / "ai.json"))
    mp.setenv("RUNTIME_SETTINGS_FILE", str(d / "runtime.json"))
    mp.setenv("AI_URL_EXTRA_PORTS", str(fake_ollama[1]))
    yield d
    mp.undo()


@pytest.fixture(autouse=True)
def reset(env, fake_ollama, monkeypatch):
    """Mỗi test bắt đầu từ cấu hình mặc định + Ollama giả; probe cloud giả."""
    from api.services import ai_probe, runtime_settings
    for f in ("ai.json", "runtime.json"):
        try:
            os.remove(env / f)
        except FileNotFoundError:
            pass
    db = SessionLocal()
    try:
        db.query(AiCredential).filter(AiCredential.scope == "user").delete()
        db.query(AiUsageEvent).delete()
        db.commit()
    finally:
        db.close()
    ai_probe._user_hits.clear(); ai_probe._global_hits.clear(); ai_probe._ollama_cache.clear()
    runtime_settings.set_ollama(url=fake_ollama[0], model="qwen2.5:7b")
    _Ollama.models = {"qwen2.5:7b": True, "llama3.2": True, "deepseek-coder:6.7b": False}
    PROBE.update(code="VALID", tools=True, latency_ms=640); PROBE_CALLS.clear()

    async def fake_probe(route, *a, **k):
        PROBE_CALLS.append((route.provider, route.model))
        assert "SECRET" not in repr(route) and "SECRET" not in str(route)          # route không bao giờ lộ secret qua repr
        ok = PROBE["code"] == "VALID"
        return ai_probe.ProbeResult(ok=ok, code=PROBE["code"], model=route.model, latency_ms=PROBE["latency_ms"], tools=PROBE["tools"] if ok else None, json=True if ok else None)
    monkeypatch.setattr(ai_probe, "probe_cloud", fake_probe)
    monkeypatch.setattr(ai_probe, "_PER_USER", 1000); monkeypatch.setattr(ai_probe, "_GLOBAL", 1000)   # throttle thật có test riêng
    yield


@pytest.fixture(scope="module")
def browser():
    with pw_sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:   # chưa cài chromium
            pytest.skip(f"Chromium không khả dụng: {e}")
        yield b
        b.close()


# ───────── helpers ─────────
def _login(page, base, email):
    page.goto(base + "/login")
    page.fill("#login-email", email)
    page.fill("#login-password", PASSWORD)
    page.click("#login-form button[type=submit]")
    page.wait_for_url(lambda u: "/login" not in u, timeout=15000)


_STATE, _IDS = {}, {}   # một lần đăng nhập mỗi role (tránh chạm giới hạn đăng nhập)


def new_ctx(browser, base, role, **kw):
    if role not in _STATE:
        c0 = browser.new_context(locale="vi-VN"); p0 = c0.new_page()
        email, uid = make_user(role)
        _login(p0, base, email)
        _STATE[role] = c0.storage_state(); _IDS[role] = (uid, email); c0.close()
    return browser.new_context(storage_state=_STATE[role], locale="vi-VN", **kw)


class Rec:
    """Ghi lại mọi request /api/* của trình duyệt để assert (method, path, body)."""

    def __init__(self, page):
        self.log = []
        page.on("request", self._on)

    def _on(self, req):
        from urllib.parse import urlparse
        u = urlparse(req.url)
        if not u.path.startswith("/api/"):
            return
        body = None
        if req.post_data:
            try:
                body = json.loads(req.post_data)
            except Exception:
                body = req.post_data
        self.log.append((req.method, u.path + (("?" + u.query) if u.query else ""), body))

    def calls(self, method=None, prefix=""):
        return [c for c in self.log if (method is None or c[0] == method) and c[1].startswith(prefix)]


def open_ai(browser, base, role, *, viewport=None, theme=None, lang=None, route=None):
    ctx = new_ctx(browser, base, role, viewport=viewport or {"width": 1280, "height": 900})
    page = ctx.new_page()
    rec = Rec(page)
    if route:
        route(page)
    page.goto(base + "/")
    page.wait_for_selector("#user-chip", state="visible", timeout=15000)
    init = []
    if theme:
        init.append(f"localStorage.setItem('vg-theme','{theme}')")
    if lang:
        init.append(f"localStorage.setItem('vg-ai-lang','{lang}')")
    if init:
        page.evaluate(";".join(init))
        page.reload()
        page.wait_for_selector("#user-chip", state="visible", timeout=15000)
    page.evaluate("navigate('settings')")
    page.wait_for_selector("#aiu-status .aiu-pill", timeout=15000)
    page.wait_for_function("() => document.querySelectorAll('#aiu-ol-model option').length > 1")     # đã nạp danh sách model Ollama
    return ctx, page, rec


def api_get(page, path):
    return page.evaluate("async (p) => { const r = await fetch(p); return {status: r.status, text: await r.text()}; }", path)


def api_json(page, path):
    r = api_get(page, path)
    assert r["status"] == 200, (path, r["status"])
    return json.loads(r["text"])


def shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f"pr5-{name}.png"), full_page=True)


def org_controls(page):
    """Mọi điều khiển sửa cấu hình tổ chức (mục 1–3 + 5)."""
    return page.locator("#aiu-sec-mode button, #aiu-sec-ollama input, #aiu-sec-ollama select, #aiu-sec-ollama button, "
                        "#aiu-sec-hybrid input, #aiu-sec-hybrid select, #aiu-sec-cloud input:not(#aiu-pv-redact):not([readonly]), "
                        "#aiu-sec-cloud select, #aiu-sec-cloud button, #aiu-sec-policy input, #aiu-sec-policy select, #aiu-sec-policy button")


def dump(page):
    return page.evaluate("""() => JSON.stringify({
        ls: Object.entries(localStorage), ss: Object.entries(sessionStorage), url: location.href,
        html: document.documentElement.outerHTML,
        inputs: [...document.querySelectorAll('input,textarea,select')].map(e => e.value),
        toasts: document.getElementById('toast-stack') ? document.getElementById('toast-stack').innerText : ''
    })""")


def save_ok(page):
    """Bấm Lưu, chờ PUT /api/ai/settings trả 200 rồi chờ trang nạp lại xong."""
    with page.expect_response(lambda r: r.url.endswith("/api/ai/settings") and r.request.method == "PUT", timeout=15000) as ri:
        page.click("#aiu-save")
    r = ri.value
    assert r.status == 200, "save failed: HTTP %s %s" % (r.status, r.text()[:300])
    page.wait_for_function("() => { const s = document.querySelector('#aiu-save'); return s.disabled && !document.querySelector('#st-ai').dataset.busy; }")


def accept_dialogs(page):
    page.on("dialog", lambda d: d.accept())


# ───────── ADMIN ─────────
def test_admin_page_on_real_backend_no_legacy_no_bridge(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        assert page.locator("#st-tab-ai").inner_text().strip() == "AI"
        for legacy in ("#st-tab-ollama", "#st-tab-ai-legacy", "#st-ollama", "#st-ai-legacy"):
            assert page.locator(legacy).count() == 0, legacy                 # hai tab cũ đã bị xoá khỏi DOM
        assert page.locator("#aiu-bridge").count() == 0
        assert "ai-legacy-on" not in (page.evaluate("document.body.className") or "")
        st = page.locator("#aiu-status").inner_text()
        assert "Local" in st and "qwen2.5:7b" in st                          # mặc định local_only + model Ollama thật
        assert page.locator("#aiu-status .aiu-pill").count() >= 3
        # ADMIN: mọi điều khiển bật, thấy mục 5 + thanh lưu
        assert page.locator("#aiu-sec-policy").is_visible() and page.locator("#aiu-savebar").is_visible()
        page.click('#aiu-modes [data-mode="hybrid"]')
        n = org_controls(page).count(); assert n > 20
        for i in range(n):
            el = org_controls(page).nth(i)
            assert el.is_enabled() or not el.is_visible()
        # 8 tile provider (PR-6) lấy từ providers_available của server
        names = page.locator("#aiu-prov button").all_inner_texts()
        for want in ("Anthropic", "Amazon Bedrock", "OpenAI", "Azure OpenAI", "Google Gemini", "Vertex AI", "OpenAI-compatible", "OpenRouter"):
            assert any(want in x for x in names), want
        # chế độ → hiện/ẩn mục
        page.click('#aiu-modes [data-mode="local_only"]')
        assert page.locator("#aiu-sec-cloud").is_hidden() and page.locator("#aiu-sec-hybrid").is_hidden() and page.locator("#aiu-sec-ollama").is_visible()
        page.click('#aiu-modes [data-mode="cloud_only"]')
        assert page.locator("#aiu-sec-ollama").is_hidden() and page.locator("#aiu-sec-cloud").is_visible() and page.locator("#aiu-sec-hybrid").is_hidden()
        page.click('#aiu-modes [data-mode="local_only"]')
        assert page.locator("#aiu-save").is_disabled()                       # quay về baseline → không có thay đổi
        # model Ollama: chỉ model đã cài (từ /api/ollama/models thật)
        opts = page.locator("#aiu-ol-model option").all_inner_texts()
        assert any("qwen2.5:7b" in o for o in opts) and any("deepseek-coder" in o for o in opts)
        # chỉ GET: xem / chuyển mode không gửi thao tác ghi nào
        assert [c for c in rec.log if c[0] != "GET"] == []
        shot(page, "admin-light-vi")
    finally:
        ctx.close()


def test_admin_save_real_api_never_keeps_or_echoes_key_and_cowork_row(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.click('#aiu-modes [data-mode="hybrid"]')
        page.fill("#aiu-anthropic-model", "claude-sonnet-5-5")
        page.fill("#aiu-anthropic-key", SECRET)
        assert page.locator("#aiu-anthropic-key").get_attribute("type") == "password"
        assert page.locator("#aiu-anthropic-key").get_attribute("autocomplete") == "new-password"
        page.select_option("#aiu-route-cw", "cloud")                         # dòng Co-work (A1) → hybrid.tasks.coworker
        assert page.locator("#aiu-p-cwcloud").count() == 0                   # không có toggle riêng
        page.click("#aiu-save")
        page.wait_for_selector("#toast-stack .toast.success")
        page.wait_for_function("() => document.querySelector('#aiu-anthropic-key').value === '' && document.querySelector('#aiu-anthropic-keyhint').innerText.includes('cdef')")
        puts = rec.calls("PUT", "/api/ai/settings")
        assert len(puts) == 1
        body = puts[0][2]
        assert body["mode"] == "hybrid" and body["anthropic"]["model"] == "claude-sonnet-5-5"
        assert body["anthropic"]["api_key"] == SECRET                        # chỉ đi trong body request
        assert body["privacy"]["redact_secrets"] is True
        assert body["hybrid"]["tasks"] == {"coworker": "cloud"}
        assert "advanced" not in body                                        # per-role model của Pentest do env, UI chỉ đọc
        # backend THẬT đã lưu — đọc lại qua API
        got = api_json(page, "/api/ai/settings")
        assert got["mode"] == "hybrid" and got["hybrid"]["tasks"]["coworker"] == "cloud"
        assert got["anthropic"]["api_key_set"] is True and got["anthropic"]["api_key_hint"].endswith("cdef")
        assert SECRET not in json.dumps(got) and "api_key_enc" not in json.dumps(got)
        assert SECRET not in api_get(page, "/api/ai/config")["text"]
        d = dump(page)
        assert SECRET not in d and SECRET[-12:] not in d
        assert "Đã lưu" in page.locator("#aiu-anthropic-keyhint").inner_text()
        # pentest per-role model: chỉ đọc
        assert page.locator("#aiu-pt-planner").get_attribute("readonly") is not None
    finally:
        ctx.close()


def test_cloud_test_uses_unsaved_values_and_maps_codes(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN, lang="en")
    try:
        page.click('#aiu-modes [data-mode="cloud_only"]')
        page.click('[data-prov="bedrock"]')
        page.select_option("#aiu-bedrock-auth", "bedrock_api_key")
        page.fill("#aiu-bedrock-region", "ap-southeast-1")
        page.fill("#aiu-bedrock-key", SECRET2)
        page.click("#aiu-cloud-test")
        page.wait_for_selector("#aiu-cloud-res.ok")
        txt = page.locator("#aiu-cloud-res").inner_text()
        assert "640 ms" in txt and "tools ✓" in txt and SECRET2 not in txt
        tests = rec.calls("POST", "/api/ai/test")
        assert len(tests) == 1
        b = tests[0][2]
        assert b["provider"] == "bedrock" and b["region"] == "ap-southeast-1" and b["auth_mode"] == "bedrock_api_key" and b["api_key"] == SECRET2
        assert PROBE_CALLS[-1][0] == "bedrock"                               # server thật đã dựng route từ giá trị chưa lưu
        assert rec.calls("PUT") == []                                        # test không lưu gì
        saved = api_json(page, "/api/ai/settings")
        assert saved["provider"] == "anthropic" and saved["bedrock"]["api_key_set"] is False and saved["bedrock"]["region"] != "ap-southeast-1"
        # lỗi: backend trả mã chuẩn hoá + câu tiếng Việt của server → UI chỉ hiện câu i18n (EN)
        PROBE["code"] = "INVALID_KEY"
        page.click("#aiu-cloud-test")
        page.wait_for_selector("#aiu-cloud-res.err")
        err = page.locator("#aiu-cloud-res").inner_text()
        assert "Key rejected" in err and "Provider từ chối" not in err and SECRET2 not in err
        PROBE["code"] = "NO_MODEL_ACCESS"
        page.click("#aiu-cloud-test")
        page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('no access')")
        st = page.evaluate("() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage), location.href, document.getElementById('toast-stack').innerText, document.getElementById('aiu-cloud-res').innerText])")
        assert SECRET2 not in st
        shot(page, "admin-test-connection-error-en")
    finally:
        ctx.close()


def test_new_providers_azure_gemini_vertex_compat_openrouter_test_and_save(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.click('#aiu-modes [data-mode="cloud_only"]')
        # Azure OpenAI: key + endpoint + deployment + api-version (Entra → tenant/client)
        page.click('[data-prov="azure_openai"]')
        assert page.locator("#aiu-azure_openai-tenant").is_hidden()
        page.select_option("#aiu-azure_openai-auth", "entra")
        assert page.locator("#aiu-azure_openai-tenant").is_visible() and page.locator("#aiu-azure_openai-client").is_visible()
        page.select_option("#aiu-azure_openai-auth", "api_key")
        page.fill("#aiu-azure_openai-endpoint", "https://myres.openai.azure.com")
        page.fill("#aiu-azure_openai-deployment", "prod-chat")
        page.fill("#aiu-azure_openai-version", "2024-10-21")
        page.fill("#aiu-azure_openai-key", AZKEY)
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.ok")
        b = rec.calls("POST", "/api/ai/test")[-1][2]
        assert b == {"provider": "azure_openai", "auth_mode": "api_key", "endpoint": "https://myres.openai.azure.com", "deployment": "prod-chat", "api_version": "2024-10-21", "api_key": AZKEY}
        assert PROBE_CALLS[-1] == ("azure_openai", "prod-chat")
        save_ok(page)
        got = api_json(page, "/api/ai/settings")
        assert got["provider"] == "azure_openai" and got["azure_openai"]["endpoint"] == "https://myres.openai.azure.com" and got["azure_openai"]["deployment"] == "prod-chat"
        assert got["azure_openai"]["api_key_set"] is True and AZKEY not in json.dumps(got)
        # Gemini
        page.click('[data-prov="gemini"]')
        page.fill("#aiu-gemini-model", "gemini-2.5-pro"); page.fill("#aiu-gemini-key", "AIzaSyFAKEKEY0123456789")
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.ok")
        assert rec.calls("POST", "/api/ai/test")[-1][2] == {"provider": "gemini", "model": "gemini-2.5-pro", "api_key": "AIzaSyFAKEKEY0123456789"}
        # Vertex AI: SA JSON (ADMIN) + project + location
        page.click('[data-prov="vertex"]')
        page.fill("#aiu-vertex-project", "my-gcp-proj-1"); page.fill("#aiu-vertex-location", "us-central1")
        page.fill("#aiu-vertex-key", SA_JSON)
        assert page.locator("#aiu-vertex-key").get_attribute("type") == "password"
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.ok")
        b = rec.calls("POST", "/api/ai/test")[-1][2]
        assert b["provider"] == "vertex" and b["project"] == "my-gcp-proj-1" and b["location"] == "us-central1" and "private_key" in b["api_key"]
        save_ok(page)
        got = api_json(page, "/api/ai/settings")
        assert got["provider"] == "vertex" and got["vertex"]["project"] == "my-gcp-proj-1" and got["vertex"]["api_key_set"] is True and got["vertex"]["api_key_hint"] == ""
        assert "MIIBVQSECRETSAKEY" not in json.dumps(got) and "MIIBVQSECRETSAKEY" not in dump(page)
        # openai_compatible (ADMIN) — qua url_guard phía server
        page.click('[data-prov="openai_compatible"]')
        page.fill("#aiu-openai_compatible-base", "https://llm.example.com/v1"); page.fill("#aiu-openai_compatible-model", "qwen3-32b")
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.ok")
        assert rec.calls("POST", "/api/ai/test")[-1][2] == {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1", "model": "qwen3-32b"}
        save_ok(page)
        got = api_json(page, "/api/ai/settings")
        assert got["provider"] == "openai_compatible" and got["openai_compatible"]["base_url"] == "https://llm.example.com/v1" and got["openai_compatible"]["model"] == "qwen3-32b"
        # OpenRouter
        page.click('[data-prov="openrouter"]')
        page.fill("#aiu-openrouter-key", "sk-or-v1-FAKEFAKEFAKEFAKE")
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.ok")
        assert rec.calls("POST", "/api/ai/test")[-1][2]["provider"] == "openrouter"
        # base_url chặn SSRF ở phía server → UI chỉ hiện mã đã dịch
        page.click('[data-prov="openai"]')
        page.fill("#aiu-openai-base", "https://169.254.169.254/v1"); page.fill("#aiu-openai-key", "sk-FAKEFAKEFAKEFAKE")
        page.click("#aiu-save")
        page.wait_for_selector("#toast-stack .toast.error")
        t = page.locator("#toast-stack .toast.error").last.inner_text()
        assert "169.254" not in t and "Base URL" in t
        shot(page, "admin-providers-azure")
    finally:
        ctx.close()


def test_ollama_capability_check_real_probe_and_missing_model(base_url, browser, fake_ollama):
    from api.services import runtime_settings
    runtime_settings.set_ollama(model="llama9:latest")                       # đã cấu hình nhưng CHƯA cài
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        sel = page.locator("#aiu-ol-model")
        assert sel.input_value() == "llama9:latest"                          # không tự đổi sang model khác
        assert page.locator("#aiu-ol-model-missing").is_visible()
        assert any("llama9" in o and "⚠" in o for o in page.locator("#aiu-ol-model option").all_inner_texts())
        page.select_option("#aiu-ol-model", "qwen2.5:7b")
        page.click("#aiu-ol-test")
        page.wait_for_selector("#aiu-ol-checks li.ok >> text=Tool-calling")
        txt = page.locator("#aiu-ol-checks").inner_text()
        assert "0.12.3" in txt and "Tool-calling" in txt and "3/3" in txt
        assert "tools ✓" in page.locator("#aiu-ol-model").inner_text()
        assert rec.calls("POST", "/api/ai/ollama/check")[-1][2]["model"] == "qwen2.5:7b"
        # model không có tool-calling → cảnh báo, không giả thành công
        page.select_option("#aiu-ol-model", "deepseek-coder:6.7b")
        page.click("#aiu-ol-test")
        page.wait_for_selector("#aiu-ol-checks li.x")
        assert "KHÔNG hỗ trợ" in page.locator("#aiu-ol-checks").inner_text()
        # lưu model + URL qua PUT /api/ai/settings → runtime_settings thật
        page.select_option("#aiu-ol-model", "llama3.2")
        save_ok(page)
        assert api_json(page, "/api/ai/settings")["ollama"]["model"] == "llama3.2"
        page.click("#aiu-ol-test")                                           # model đã lưu được kiểm → pill trạng thái hiện tool-calling
        page.wait_for_function("() => document.querySelector('#aiu-status').innerText.includes('tool-calling')")
        # Ollama không với tới (cổng được phép nhưng không có server) → mã lỗi đã dịch, không giả thành công
        page.fill("#aiu-ol-url", "http://127.0.0.1:%d" % (fake_ollama[1] + 1))
        page.click("#aiu-ol-test")
        page.wait_for_selector("#aiu-ol-checks li.x")
        shot(page, "admin-ollama-check")
    finally:
        ctx.close()


def test_inline_validation_blocks_save(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.click('#aiu-modes [data-mode="hybrid"]')
        page.fill("#aiu-h-lo", "90"); page.fill("#aiu-h-hi", "10")
        page.fill("#aiu-ol-url", "ftp://nope user@x")
        page.click("#aiu-save")
        assert page.locator("#aiu-h-err").inner_text().strip() != "" and page.locator("#aiu-ol-url-err").inner_text().strip() != ""
        assert rec.calls("PUT") == []
        page.click('[data-prov="azure_openai"]')
        page.fill("#aiu-azure_openai-endpoint", "https://evil.example.com")
        page.click("#aiu-save")
        assert page.locator("#aiu-azure_openai-endpointerr").inner_text().strip() != ""
        assert rec.calls("PUT") == []
        page.click("#aiu-discard")
        assert page.locator("#aiu-h-lo").input_value() == "15"
        assert page.locator("#aiu-save").is_disabled()
    finally:
        ctx.close()


def test_admin_policy_azure_mapping_usage_and_revoke(base_url, browser):
    ctx_a, page_a, rec_a = open_ai(browser, base_url, UserRole.ANALYST)       # tạo _IDS[ANALYST]
    ctx_a.close()
    analyst_id, analyst_email = _IDS[UserRole.ANALYST]
    from api.services import ai_credentials as creds, ai_usage
    db = SessionLocal()
    try:
        m = creds.create(db, scope="user", owner_user_id=analyst_id, provider="bedrock", label="analyst-bedrock", auth_mode="bedrock_api_key",
                         secret="ABSKANALYSTOWNSECRET0123456789ab9fA1", params={"model": "anthropic.claude-opus-5-5", "region": "us-east-1"}, created_by=analyst_id, status="valid")
        db.commit(); cid = m["id"]
    finally:
        db.close()
    ai_usage.record(user_id=analyst_id, credential_id=cid, scope="user", provider="bedrock", model="anthropic.claude-opus-5-5", feature="triage", tokens_in=1000, tokens_out=200)
    admin_id = _IDS.get(UserRole.ADMIN, (None,))[0]
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    accept_dialogs(page)
    try:
        admin_id = _IDS[UserRole.ADMIN][0]
        ai_usage.record(user_id=admin_id, credential_id=None, scope="org", provider="anthropic", model="claude-opus-5-5", feature="reanalyze", tokens_in=5000, tokens_out=800)
        page.reload(); page.wait_for_selector("#user-chip", state="visible"); page.evaluate("navigate('settings')")
        page.wait_for_selector("#aiu-ukeys tr[data-id], #aiu-ukeys td")
        page.wait_for_function("() => document.querySelector('#aiu-ukeys').innerText.includes('analyst-bedrock') || document.querySelector('#aiu-ukeys').innerText.includes('9fA1')")
        uk = page.locator("#aiu-ukeys").inner_text()
        assert analyst_email in uk and "9fA1" in uk and "ABSKANALYSTOWNSECRET" not in uk
        us = page.locator("#aiu-usage").inner_text()
        assert analyst_email in us and "9fA1" in us and "Bedrock" in us
        assert "ABSKANALYSTOWNSECRET" not in dump(page)
        # chính sách + ánh xạ Azure deployment → model (REPLACE)
        page.select_option("#aiu-p-byok", "required"); page.select_option("#aiu-p-fallback", "0")
        page.fill("#aiu-p-allowed", "anthropic:*, bedrock:*claude*, azure_openai:gpt-4o")
        page.fill("#aiu-p-usd", "20"); page.fill("#aiu-p-rpm", "60")
        page.select_option("#aiu-p-sched", "local_only"); page.select_option("#aiu-p-baseurl", "off")
        page.click("#aiu-azmap-add")
        row = page.locator("#aiu-azmap .aiu-azrow").nth(0)
        row.locator('[data-az="res"]').fill("MyRes"); row.locator('[data-az="dep"]').fill("Prod-Chat"); row.locator('[data-az="model"]').fill("gpt-4o")
        page.click("#aiu-azmap-add")
        row2 = page.locator("#aiu-azmap .aiu-azrow").nth(1)
        row2.locator('[data-az="res"]').fill("myres"); row2.locator('[data-az="dep"]').fill("old"); row2.locator('[data-az="model"]').fill("gpt-4o-mini")
        save_ok(page)
        pol = api_json(page, "/api/ai/settings")["policy"]
        assert pol["byok"] == "required" and pol["fallback_to_org"] is False and pol["scheduled_jobs_credential"] == "local_only" and pol["custom_base_url"] == "off"
        assert pol["org_quota"] == {"usd_per_user_month": 20, "rpm_per_user": 60}
        assert pol["azure_deployment_models"] == {"myres/prod-chat": "gpt-4o", "myres/old": "gpt-4o-mini"}
        # xoá một mục → server thay thế toàn bộ object
        page.locator("#aiu-azmap .aiu-azrow").nth(1).locator('[data-act="az-del"]').click()
        save_ok(page)
        assert api_json(page, "/api/ai/settings")["policy"]["azure_deployment_models"] == {"myres/prod-chat": "gpt-4o"}
        page.reload(); page.wait_for_selector("#user-chip", state="visible"); page.evaluate("navigate('settings')")
        page.wait_for_selector("#aiu-azmap .aiu-azrow")
        assert page.locator('#aiu-azmap [data-az="dep"]').first.input_value() == "prod-chat" and page.locator("#aiu-p-usd").input_value() == "20"
        # quota_pct của khoá org hiện trong bảng usage khi có hạn mức
        page.wait_for_function("() => document.querySelector('#aiu-usage').innerText.includes('%')")
        shot(page, "admin-policy-usage")
        # thu hồi khoá của user
        page.click(f'#aiu-ukeys [data-act="uk-revoke"][data-id="{cid}"]')
        page.wait_for_selector("#toast-stack .toast.success")
        db = SessionLocal()
        try:
            assert db.get(AiCredential, cid).status == "revoked" and db.get(AiCredential, cid).secret_enc is None
        finally:
            db.close()
    finally:
        ctx.close()


# ───────── ANALYST ─────────
def test_analyst_readonly_org_but_my_keys_end_to_end(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ANALYST)
    accept_dialogs(page)
    try:
        assert page.locator("#aiu-ro").is_visible()
        n = org_controls(page).count(); assert n > 5
        for i in range(n):
            el = org_controls(page).nth(i)
            assert el.is_disabled() or not el.is_visible(), el.evaluate("e => e.id || e.outerHTML.slice(0,80)")
        assert page.locator("#aiu-savebar").is_hidden() and page.locator("#aiu-sec-policy").is_hidden()
        assert page.locator("#aiu-sec-mine").is_visible() and page.locator("#aiu-add-btn").is_enabled()
        assert "policy" not in api_json(page, "/api/ai/settings")                 # server không đưa policy cho non-ADMIN
        assert api_get(page, "/api/ai/credentials")["status"] == 403
        # ── thêm khoá lỗi: không lưu, không echo, ô key được xoá ──
        PROBE["code"] = "INVALID_KEY"
        page.click("#aiu-add-btn"); page.select_option("#aiu-add-prov", "anthropic"); page.fill("#aiu-add-key", SECRET3)
        page.click("#aiu-add-go")
        page.wait_for_function("() => document.querySelector('#aiu-add-err').textContent.trim() !== ''")
        assert "401" in page.locator("#aiu-add-err").inner_text() and SECRET3 not in page.locator("#aiu-add-err").inner_text()
        assert page.locator("#aiu-add-key").input_value() == ""
        assert api_json(page, "/api/me/ai-credentials")["credentials"] == []
        # ── thêm khoá hợp lệ (create = validate rồi lưu) ──
        PROBE["code"] = "VALID"
        page.fill("#aiu-add-key", SECRET3); page.fill("#aiu-add-label", "work")
        page.click("#aiu-add-go")
        page.wait_for_selector('#aiu-mine-table tr[data-id]')
        row = page.locator("#aiu-mine-table tr[data-id]").first
        assert "9988" in row.inner_text() and "work" in row.inner_text() and row.locator(".aiu-tag.b").count() == 1      # mặc định
        cid = row.get_attribute("data-id")
        assert rec.calls("POST", "/api/me/ai-credentials")[-1][2]["secret"] == SECRET3
        api = api_json(page, "/api/me/ai-credentials")
        assert api["credentials"][0]["id"] == cid and api["credentials"][0]["key_hint"].endswith("9988") and SECRET3 not in json.dumps(api)
        assert SECRET3 not in dump(page)
        assert "9988" in page.locator("#aiu-status").inner_text()                # pill "Khoá của bạn"
        # ── Azure OpenAI: chỉ tên resource + deployment (D4) ──
        page.click("#aiu-add-btn"); page.select_option("#aiu-add-prov", "azure_openai")
        assert page.locator("#aiu-add-model-wrap").is_hidden() and page.locator("#aiu-add-az-wrap").is_visible()
        page.fill("#aiu-add-key", AZKEY); page.fill("#aiu-add-resource", "myres"); page.fill("#aiu-add-deployment", "prod-chat")
        page.click("#aiu-add-go")
        page.wait_for_function("() => document.querySelectorAll('#aiu-mine-table tr[data-id]').length === 2")
        body = rec.calls("POST", "/api/me/ai-credentials")[-1][2]
        assert body["resource"] == "myres" and body["deployment"] == "prod-chat" and "endpoint" not in body and "base_url" not in body
        # ── Bedrock với region ──
        page.click("#aiu-add-btn"); page.select_option("#aiu-add-prov", "bedrock")
        page.fill("#aiu-add-region", "ap-southeast-1"); page.fill("#aiu-add-key", SECRET2)
        page.click("#aiu-add-go")
        page.wait_for_function("() => document.querySelectorAll('#aiu-mine-table tr[data-id]').length === 3")
        assert "ap-southeast-1" in page.locator("#aiu-mine-table").inner_text()
        # ── Test khoá đã lưu ──
        page.click(f'#aiu-mine-table tr[data-id="{cid}"] [data-act=c-test]')
        page.wait_for_function("() => document.querySelector('#aiu-mine-msg').textContent.includes('✓')")
        # ── Xoay khoá: sai → khoá cũ giữ nguyên; đúng → hint đổi ──
        page.click(f'#aiu-mine-table tr[data-id="{cid}"] [data-act=c-rot]')
        PROBE["code"] = "INVALID_KEY"
        page.fill("#aiu-rot-key", SECRET4); page.click('[data-act="c-rot-go"]')
        page.wait_for_function("() => (document.querySelector('#aiu-rot-err')||{textContent:''}).textContent.trim() !== ''")
        assert "9988" in [c for c in api_json(page, "/api/me/ai-credentials")["credentials"] if c["id"] == cid][0]["key_hint"]
        PROBE["code"] = "VALID"
        page.fill("#aiu-rot-key", SECRET4); page.click('[data-act="c-rot-go"]')
        page.wait_for_function("() => document.querySelector('#aiu-mine-table').innerText.includes('7766')")
        assert SECRET3 not in dump(page) and SECRET4 not in dump(page)
        # ── Đặt mặc định + xoá ──
        other = [r.get_attribute("data-id") for r in page.locator("#aiu-mine-table tr[data-id]").all() if r.get_attribute("data-id") != cid][0]
        page.click(f'#aiu-mine-table tr[data-id="{other}"] [data-act=c-def]')
        page.wait_for_function("(id) => document.querySelector(`#aiu-mine-table tr[data-id=\"${id}\"] .aiu-tag.b`) !== null", arg=other)
        page.click(f'#aiu-mine-table tr[data-id="{cid}"] [data-act=c-del]')
        page.wait_for_function("() => document.querySelectorAll('#aiu-mine-table tr[data-id]').length === 2")
        left = api_json(page, "/api/me/ai-credentials")["credentials"]
        assert cid not in [c["id"] for c in left] and SECRET4 not in json.dumps(left)
        db = SessionLocal()
        try:
            row = db.get(AiCredential, cid); assert row.status == "revoked" and row.secret_enc is None      # xoá secret ngay
        finally:
            db.close()
        # ANALYST không gọi bất kỳ endpoint ADMIN nào / không PUT cấu hình
        assert rec.calls("PUT", "/api/ai/settings") == [] and len(rec.calls(None, "/api/ai/credentials")) == 1      # chỉ lần gọi 403 chủ động ở đầu test
        assert all("scope=all" not in c[1] for c in rec.calls(None, "/api/ai/usage"))
        shot(page, "analyst-my-keys")
    finally:
        ctx.close()


def test_analyst_probe_throttle_is_mapped_not_echoed(base_url, browser, monkeypatch):
    from api.services import ai_probe
    monkeypatch.setattr(ai_probe, "_PER_USER", 1)
    ctx, page, rec = open_ai(browser, base_url, UserRole.ANALYST)
    try:
        page.click("#aiu-add-btn"); page.fill("#aiu-add-key", SECRET3); page.click("#aiu-add-go")
        page.wait_for_selector("#aiu-mine-table tr[data-id]")                  # lần 1 qua
        page.click("#aiu-add-btn"); page.select_option("#aiu-add-prov", "openai"); page.fill("#aiu-add-key", "sk-FAKEFAKEFAKEFAKE"); page.click("#aiu-add-go")
        page.wait_for_function("() => document.querySelector('#aiu-add-err').textContent.trim() !== ''")
        assert "Quá nhiều" in page.locator("#aiu-add-err").inner_text() and page.locator("#aiu-add-key").input_value() == ""
    finally:
        ctx.close()


def test_analyst_byok_off_disables_add_and_maps_code(base_url, browser):
    from api.services.ai_config import validate_and_save
    validate_and_save({"policy": {"byok": "off"}})
    ctx, page, rec = open_ai(browser, base_url, UserRole.ANALYST)
    try:
        assert page.locator("#aiu-add-btn").is_disabled()
        assert "tắt" in page.locator("#aiu-policy-note").inner_text().lower() or "off" in page.locator("#aiu-policy-note").inner_text().lower() or page.locator("#aiu-policy-note").inner_text().strip() != ""
        r = page.evaluate("""async () => { const r = await fetch('/api/me/ai-credentials', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({provider:'anthropic', secret:'sk-ant-api03-xxxxxxxxxxxx'})}); return {s: r.status, t: await r.text()}; }""")
        assert r["s"] == 403 and "AI_BYOK_OFF" in r["t"]                      # server cưỡng chế, UI chỉ phản ánh
    finally:
        ctx.close()


# ───────── VIEWER ─────────
def test_viewer_readonly_and_no_personal_keys(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.VIEWER)
    try:
        assert page.locator("#aiu-ro").is_visible()
        assert page.locator("#aiu-sec-mine").is_hidden() and page.locator("#aiu-sec-policy").is_hidden() and page.locator("#aiu-savebar").is_hidden()
        for i in range(org_controls(page).count()):
            el = org_controls(page).nth(i)
            assert el.is_disabled() or not el.is_visible()
        assert rec.calls(None, "/api/me/ai-credentials") == [] and rec.calls(None, "/api/ai/usage") == [] and rec.calls(None, "/api/ai/credentials") == []
        assert api_get(page, "/api/me/ai-credentials")["status"] == 403
        assert api_get(page, "/api/ai/usage?scope=me")["status"] == 403
        st = api_json(page, "/api/ai/settings")
        assert "policy" not in st and st["status"]["mine"]["source"] == "none"
        shot(page, "viewer-light-vi")
    finally:
        ctx.close()


# ───────── chung ─────────
def test_language_switch_vi_en_and_persistence(base_url, browser):
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        assert page.locator("#aiu-lang .on").inner_text() == "VI"
        assert "Nơi xử lý" in page.locator("#aiu-sec-mode h3").inner_text()
        page.click('#aiu-lang [data-v="en"]')
        page.wait_for_function("() => document.querySelector('#aiu-sec-mode h3').innerText.includes('Where AI runs')")
        assert page.locator("#aiu-modes").inner_text().count("Local") >= 1
        page.reload(); page.wait_for_selector("#user-chip", state="visible"); page.evaluate("navigate('settings')")
        page.wait_for_function("() => document.querySelector('#aiu-sec-mode h3').innerText.includes('Where AI runs')")
        shot(page, "admin-light-en")
    finally:
        ctx.close()


def test_dark_theme_and_mobile_390_no_horizontal_overflow(base_url, browser):
    for role, name in ((UserRole.ADMIN, "admin"), (UserRole.ANALYST, "analyst"), (UserRole.VIEWER, "viewer")):
        ctx, page, rec = open_ai(browser, base_url, role, viewport={"width": 390, "height": 844}, theme="dark", lang="en")
        try:
            page.click('#aiu-modes [data-mode="hybrid"]') if role == UserRole.ADMIN else None
            ow = page.evaluate("() => ({sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth})")
            assert ow["sw"] <= ow["cw"] + 1, (name, ow)
            shot(page, f"{name}-dark-390-en")
        finally:
            ctx.close()
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN, theme="dark")
    try:
        shot(page, "admin-dark-vi")
    finally:
        ctx.close()


def test_old_anchors_redirect_to_new_ones(base_url, browser):
    ctx = new_ctx(browser, base_url, UserRole.ADMIN, viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    try:
        page.goto(base_url + "/#st-ollama")
        page.wait_for_selector("#aiu-status .aiu-pill", timeout=15000)
        page.wait_for_function("() => location.hash === '#ollama'")
        page.goto(base_url + "/#st-ai")
        page.reload()
        page.wait_for_function("() => location.hash === '#mode'")
    finally:
        ctx.close()


LEAK_KEY = "sk-ant-api03-LEAKEDKEY-ZZZ999888777"
LEAK_URL = "https://evil.example/v1/messages?token=LEAKEDTOKEN123"
LEAK_BODY = f"Error code: 401 - invalid x-api-key {LEAK_KEY} at {LEAK_URL} request_id=req_LEAK"


def _no_leak(page):
    html = page.evaluate("() => document.documentElement.outerHTML + ' ' + [...document.querySelectorAll('input,textarea')].map(e => e.value).join(' ')")
    for bad in ("LEAKEDKEY", "LEAKEDTOKEN", "evil.example", "req_LEAK", "invalid x-api-key", "Error code: 401"):
        assert bad not in html, bad


def _fulfill(page, pattern, body, status=200, method=None):
    def h(r):
        if method and r.request.method != method:
            return r.fallback()
        r.fulfill(status=status, content_type="application/json", body=json.dumps(body))
    page.route(pattern, h)


def test_server_error_text_is_never_rendered_only_mapped_codes(base_url, browser):
    """Server/provider độc hại (đã bị chặn response) không bao giờ làm UI render text của họ."""
    ctx, page, rec = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        # 1) ok:false + code + text của provider → chỉ câu i18n của UI
        _fulfill(page, "**/api/ai/test", {"ok": False, "provider": "anthropic", "code": "INVALID_KEY", "error": LEAK_BODY}, method="POST")
        page.click('#aiu-modes [data-mode="cloud_only"]')
        page.click("#aiu-cloud-test"); page.wait_for_selector("#aiu-cloud-res.err")
        assert "401" in page.locator("#aiu-cloud-res").inner_text()
        _no_leak(page)
        # 2) code lạ + message → câu chung đã dịch
        page.unroute("**/api/ai/test")
        _fulfill(page, "**/api/ai/test", {"ok": False, "code": "WEIRD_NEW_CODE", "error": LEAK_BODY, "message": LEAK_BODY}, method="POST")
        page.click("#aiu-cloud-test"); page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('Có lỗi xảy ra')")
        _no_leak(page)
        # 3) chỉ có text thô, không có code → câu chung
        page.unroute("**/api/ai/test")
        _fulfill(page, "**/api/ai/test", {"ok": False, "provider": "anthropic", "error": LEAK_BODY}, method="POST")
        page.click("#aiu-cloud-test"); page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('Có lỗi xảy ra')")
        _no_leak(page)
        # 4) tiền tố "[auth_failed] …" → chỉ lấy mã
        page.unroute("**/api/ai/test")
        _fulfill(page, "**/api/ai/test", {"ok": False, "provider": "anthropic", "error": "[auth_failed] " + LEAK_BODY}, method="POST")
        page.click("#aiu-cloud-test"); page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('401')")
        _no_leak(page)
        # 5) HTTP 500 với body có detail chứa key + URL
        page.unroute("**/api/ai/test")
        _fulfill(page, "**/api/ai/test", {"detail": LEAK_BODY}, status=500, method="POST")
        page.click("#aiu-cloud-test"); page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('Có lỗi xảy ra')")
        _no_leak(page)
        # 6) EN
        page.click('#aiu-lang [data-v="en"]')
        page.wait_for_selector("#aiu-cloud-res", state="hidden")
        page.click("#aiu-cloud-test")
        page.wait_for_function("() => document.querySelector('#aiu-cloud-res').innerText.includes('Something went wrong')")
        _no_leak(page)
        # 7) lưu thất bại (422 + detail chuỗi có tiền tố mã + key/URL) → chỉ mã đã dịch / câu chung
        _fulfill(page, "**/api/ai/settings", {"detail": "BAD_BASE_URL: " + LEAK_BODY}, status=422, method="PUT")
        page.click('#aiu-modes [data-mode="hybrid"]'); page.fill("#aiu-anthropic-key", SECRET)
        page.click("#aiu-save")
        page.wait_for_selector("#toast-stack .toast.error")
        _no_leak(page)
        assert "Base URL" in page.locator("#toast-stack .toast.error").last.inner_text()
        # 8) Ollama check lỗi + text
        _fulfill(page, "**/api/ai/ollama/check", {"ok": False, "code": "NETWORK", "error": LEAK_BODY}, method="POST")
        page.click("#aiu-ol-test"); page.wait_for_selector("#aiu-ol-checks li.x")
        _no_leak(page)
    finally:
        ctx.close()
    ctx, page, rec = open_ai(browser, base_url, UserRole.ANALYST)
    try:
        PROBE["code"] = "VALID"
        page.click("#aiu-add-btn"); page.fill("#aiu-add-key", SECRET3); page.click("#aiu-add-go")
        page.wait_for_selector("#aiu-mine-table tr[data-id]")
        cid = page.locator("#aiu-mine-table tr[data-id]").first.get_attribute("data-id")
        _fulfill(page, f"**/api/me/ai-credentials/{cid}/test", {"ok": False, "code": "NO_MODEL_ACCESS", "error": LEAK_BODY}, method="POST")
        page.click(f'#aiu-mine-table tr[data-id="{cid}"] [data-act=c-test]')
        page.wait_for_function("() => document.querySelector('#aiu-mine-msg').textContent.includes('✗')")
        _no_leak(page)
        _fulfill(page, "**/api/me/ai-credentials", {"detail": LEAK_BODY}, status=422, method="POST")
        page.click("#aiu-add-btn"); page.fill("#aiu-add-key", SECRET); page.click("#aiu-add-go")
        page.wait_for_function("() => document.querySelector('#aiu-add-err').textContent.trim() !== ''")
        _no_leak(page)
    finally:
        ctx.close()
