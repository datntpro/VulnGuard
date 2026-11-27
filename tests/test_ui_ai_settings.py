"""E2E (Chromium headless): Settings › AI hợp nhất (PR-5, refs #109). Bỏ qua nếu thiếu Playwright/Chromium.

Backend khoá-theo-người (PR-1..PR-4) chưa merge → các endpoint §6 mới (/api/ai/settings, /api/me/ai-credentials …) được
GIẢ LẬP ở tầng mạng của trình duyệt bằng page.route(), theo đúng hợp đồng trong docs/ai-settings-web-contract.md.
Phần còn lại (đăng nhập, role, /api/auth/me, static, CSP) chạy trên app thật. Mọi request tới endpoint giả đều được ghi lại
để assert: không gửi thao tác ADMIN khi role không đủ, key không bị echo, test dùng giá trị CHƯA LƯU.

Ảnh chụp (light/dark, VI/EN, 3 role, 390 px) ghi ra thư mục AI_UI_SHOTS nếu biến môi trường này được đặt.
"""
import json
import os
import socket
import threading
import time

import pytest

pw_sync = pytest.importorskip("playwright.sync_api")

import uvicorn

from api.auth_models import UserRole
from api.main import app
from tests._authutil import PASSWORD, make_user

SECRET = "sk-ant-api03-SUPERSECRETVALUE-0123456789abcdef"
SECRET2 = "ABSKQmVkcm9ja0FQSUtleS1TRUNSRVQtMDEyMzQ1Njc4OQ=="
SHOTS = os.environ.get("AI_UI_SHOTS")


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
def browser():
    with pw_sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:   # chưa cài chromium
            pytest.skip(f"Chromium không khả dụng: {e}")
        yield b
        b.close()


# ───────── hợp đồng giả lập (§6) ─────────
def settings_fixture(role="ADMIN", **over):
    d = {
        "mode": "hybrid", "provider": "anthropic",
        "anthropic": {"auth_mode": "api_key", "model": "claude-opus-5-5", "api_key_set": True, "api_key_hint": "…7Qx2",
                      "api_key_saved_by": "admin@x", "api_key_saved_at": "2026-11-12T08:00:00Z", "wif": {}},
        "bedrock": {"auth_mode": "aws_chain", "region": "us-east-1", "aws_profile": "", "model": "anthropic.claude-opus-5-5", "api_key_set": False, "api_key_hint": ""},
        "openai": {"model": "gpt-4o", "base_url": "", "api_key_set": False, "api_key_hint": ""},
        "openrouter": {"model": "anthropic/claude-3.5-sonnet", "api_key_set": False, "api_key_hint": ""},
        "hybrid": {"escalate_min_severity": "HIGH", "fp_band_low": 15, "fp_band_high": 85},
        "privacy": {"send_code_context": True, "context_lines": 15, "redact_secrets": True},
        "ollama": {"url": "http://host.docker.internal:11434", "custom": False, "default_url": "http://host.docker.internal:11434",
                   "model": "qwen2.5:7b", "vision_model": "", "reachable": True, "latency_ms": 182, "version": "0.12",
                   "installed": [{"name": "qwen2.5:7b", "size_gb": 4.7, "tools": True},
                                 {"name": "llama3.2", "size_gb": 2.0, "tools": True},
                                 {"name": "deepseek-coder:6.7b", "size_gb": 3.8, "tools": False}]},
        "providers_available": ["anthropic", "bedrock", "openai", "openrouter"],
        "preview": {"scan": "x", "items": [["CRITICAL", None], ["HIGH", 40], ["MEDIUM", 50], ["MEDIUM", 5], ["LOW", 90], ["LOW", 20]]},
        "policy_public": {"byok": "allowed", "allowed": ["anthropic:*", "bedrock:*claude*"], "fallback_to_org": True, "usd_per_user_month": 20},
        "status": {"ollama": {"reachable": True, "latency_ms": 182, "model": "qwen2.5:7b", "tools": True},
                   "cloud": {"provider": "anthropic", "configured": True, "last_test_at": "2026-11-24T08:00:00Z", "last_test_ok": True},
                   "mine": {"source": "own", "provider": "bedrock", "hint": "…9fA1"}},
    }
    if role == "ADMIN":
        d["policy"] = {"byok": "allowed", "fallback_to_org": True, "allowed": ["anthropic:*", "bedrock:*claude*"],
                       "org_quota": {"usd_per_user_month": 20, "rpm_per_user": 60}, "scheduled_jobs_credential": "org", "custom_base_url": "admin_only"}
        d["advanced"] = {"pentest_models": {"planner": "claude-opus-5-5", "executor": "", "summarizer": ""}}
    d.update(over)
    return d


CREDS = [
    {"id": "c1", "provider": "bedrock", "label": "personal", "key_hint": "…9fA1", "model": "us.anthropic.claude-sonnet-5-5", "region": "us-east-1", "status": "valid", "last_validated_at": "2026-11-27T06:00:00Z", "is_default": True},
    {"id": "c2", "provider": "anthropic", "label": "", "key_hint": "…2kQe", "model": "claude-opus-5-5", "status": "invalid", "last_validated_at": "2026-11-26T06:00:00Z", "is_default": False},
]


class Contract:
    """Server giả của hợp đồng §6, ghi lại mọi request để test assert."""

    def __init__(self, page, role="ADMIN", settings=None):
        self.log = []          # (method, path, body|None)
        self.role = role
        self.settings = settings or settings_fixture(role)
        self.creds = [dict(c) for c in CREDS]
        self.test_result = {"ok": True, "provider": "anthropic", "model": "claude-opus-5-5", "latency_ms": 640, "tools": True, "json": True, "code": "VALID"}
        self.check_result = {"ok": True, "latency_ms": 182, "version": "0.12", "model_loaded": True, "tools": True, "json_ok": 2, "json_total": 3}
        self.create_result = None
        page.route("**/api/ai/**", self.handle)
        page.route("**/api/me/ai-credentials**", self.handle)
        page.route("**/api/ollama/**", self.handle)

    def calls(self, method=None, prefix=""):
        return [c for c in self.log if (method is None or c[0] == method) and c[1].startswith(prefix)]

    def handle(self, route):
        req = route.request
        from urllib.parse import urlparse
        path = urlparse(req.url).path
        body = None
        if req.post_data:
            try:
                body = json.loads(req.post_data)
            except Exception:
                body = req.post_data
        self.log.append((req.method, path, body))

        def ok(data, status=200):
            route.fulfill(status=status, content_type="application/json", body=json.dumps(data))

        m = req.method
        if path == "/api/ai/settings":
            if m == "GET":
                return ok(self.settings)
            if m == "PUT":
                if self.role != "ADMIN":
                    return ok({"detail": "forbidden"}, 403)
                for k, v in body.items():
                    if isinstance(v, dict) and isinstance(self.settings.get(k), dict):
                        for kk, vv in v.items():
                            if kk == "api_key":
                                self.settings[k]["api_key_set"] = True
                                self.settings[k]["api_key_hint"] = "…" + vv[-4:]
                            elif kk != "api_key":
                                self.settings[k][kk] = vv
                    else:
                        self.settings[k] = v
                return ok(self.settings)
        if path == "/api/ai/test" and m == "POST":
            return ok(self.test_result)
        if path == "/api/ai/ollama/check" and m == "POST":
            return ok(self.check_result)
        if path == "/api/me/ai-credentials":
            if m == "GET":
                return ok({"credentials": self.creds})
            if m == "POST":
                if self.create_result:
                    return ok(*self.create_result)
                self.creds.append({"id": "c3", "provider": body["provider"], "label": body.get("label") or "", "key_hint": "…" + body["secret"][-4:],
                                   "model": body.get("model"), "status": "valid", "last_validated_at": "2026-11-27T07:00:00Z", "is_default": False})
                return ok(self.creds[-1], 201)
        if path.startswith("/api/me/ai-credentials/"):
            if path.endswith("/test"):
                return ok(self.test_result)
            if m == "DELETE":
                cid = path.rsplit("/", 1)[1]
                self.creds = [c for c in self.creds if c["id"] != cid]
                return ok(None, 204) if False else route.fulfill(status=204)
            return ok({"ok": True})
        if path == "/api/ai/credentials":
            return ok({"credentials": [{"id": "u1", "owner": {"email": "an1@x"}, "provider": "bedrock", "key_hint": "…9fA1", "status": "valid", "last_used_at": "2026-11-27T05:00:00Z"}]})
        if path == "/api/ai/usage":
            return ok({"rows": [{"user_email": "an1@x", "credential_scope": "user", "provider": "bedrock", "key_hint": "…9fA1", "calls": 412, "est_cost_usd": None},
                                {"user_email": "pentester@x", "credential_scope": "org", "provider": "anthropic", "key_hint": "…7Qx2", "calls": 1280, "est_cost_usd": 17.4, "quota_pct": 87}]})
        if path == "/api/ai/models":
            return ok({"provider": "anthropic", "models": ["claude-opus-5-5", "claude-sonnet-5-5"], "source": "api"})
        route.fallback()


def _login(page, base, email):
    page.goto(base + "/login")
    page.fill("#login-email", email)
    page.fill("#login-password", PASSWORD)
    page.click("#login-form button[type=submit]")
    page.wait_for_url(lambda u: "/login" not in u, timeout=15000)


def open_ai(browser, base, role, *, viewport=None, theme=None, lang=None, contract=True, settings=None):
    ctx = browser.new_context(viewport=viewport or {"width": 1280, "height": 900}, locale="vi-VN")
    page = ctx.new_page()
    c = Contract(page, role.name, settings) if contract else None
    email, _ = make_user(role)
    _login(page, base, email)
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
    page.wait_for_selector("#aiu-status .aiu-pill", timeout=15000) if contract else page.wait_for_selector("#aiu-status", timeout=15000)
    return ctx, page, c


def shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f"pr5-{name}.png"), full_page=True)


def org_controls(page):
    """Mọi điều khiển sửa cấu hình tổ chức (mục 1–3 + 5)."""
    return page.locator("#aiu-sec-mode button, #aiu-sec-ollama input, #aiu-sec-ollama select, #aiu-sec-ollama button, "
                        "#aiu-sec-hybrid input, #aiu-sec-hybrid select, #aiu-sec-cloud input:not(#aiu-pv-redact), "
                        "#aiu-sec-cloud select, #aiu-sec-cloud button:not([data-soon])")


# ───────── ADMIN ─────────
def test_admin_full_page_mode_switching_and_status(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        assert page.locator("#st-tab-ai").inner_text().strip() == "AI"
        assert not page.locator("#st-tab-ollama").is_visible()          # 2 tab cũ ẩn khi backend đã có /api/ai/settings
        assert not page.locator("#st-tab-ai-legacy").is_visible()
        assert page.locator("#aiu-bridge").is_hidden()
        assert page.locator("#aiu-status .aiu-pill").count() == 4
        assert "Hybrid" in page.locator("#aiu-status").inner_text()
        assert "…9fA1" in page.locator("#aiu-status").inner_text()       # pill "Khoá của bạn"
        # ADMIN: mọi điều khiển bật, thấy mục 5 + thanh lưu
        assert page.locator("#aiu-sec-policy").is_visible() and page.locator("#aiu-savebar").is_visible()
        n = org_controls(page).count(); assert n > 10
        for i in range(n):
            assert org_controls(page).nth(i).is_enabled() or not org_controls(page).nth(i).is_visible()
        # chuyển chế độ → hiện/ẩn mục
        page.click('#aiu-modes [data-mode="local_only"]')
        assert page.locator("#aiu-sec-cloud").is_hidden() and page.locator("#aiu-sec-hybrid").is_hidden() and page.locator("#aiu-sec-ollama").is_visible()
        page.click('#aiu-modes [data-mode="cloud_only"]')
        assert page.locator("#aiu-sec-ollama").is_hidden() and page.locator("#aiu-sec-cloud").is_visible() and page.locator("#aiu-sec-hybrid").is_hidden()
        page.click('#aiu-modes [data-mode="hybrid"]')
        assert page.locator("#aiu-sec-hybrid").is_visible() and page.locator("#aiu-sec-ollama").is_visible() and page.locator("#aiu-sec-cloud").is_visible()
        assert page.locator('#aiu-modes [data-mode="hybrid"]').get_attribute("aria-checked") == "true"
        assert "1" in page.locator("#aiu-unsaved").inner_text() or page.locator("#aiu-save").is_disabled()
        # pill trạng thái đổi theo chế độ nhưng chưa lưu → vẫn Hybrid ở baseline? (dirty = 0 vì quay lại hybrid)
        assert page.locator("#aiu-save").is_disabled()
        # model Ollama: chỉ model đã cài + tag tools
        opts = page.locator("#aiu-ol-model option").all_inner_texts()
        assert any("qwen2.5:7b" in o and "tools ✓" in o for o in opts) and any("deepseek-coder" in o and "tools ✗" in o for o in opts)
        # preview tính theo quy tắc hiện tại (HIGH+ hoặc FP 15–85): CRITICAL, HIGH, MEDIUM(50), LOW(20) = 4/6
        assert "4/6" in page.locator("#aiu-h-preview").inner_text()
        page.fill("#aiu-h-lo", "60")      # band 60–85: chỉ CRITICAL + HIGH + LOW(90 ngoài) → 2/6
        page.fill("#aiu-h-hi", "85")
        assert "2/6" in page.locator("#aiu-h-preview").inner_text()
        shot(page, "admin-light-vi")
        # không có request ADMIN nào bị gửi chỉ vì xem/chuyển mode
        assert c.calls("PUT") == []
    finally:
        ctx.close()


def test_admin_save_sends_payload_and_never_keeps_or_echoes_key(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.click('#aiu-modes [data-mode="cloud_only"]')
        page.fill("#aiu-anthropic-model", "claude-sonnet-5-5")
        page.fill("#aiu-anthropic-key", SECRET)
        assert page.locator("#aiu-anthropic-key").get_attribute("type") == "password"
        assert page.locator("#aiu-anthropic-key").get_attribute("autocomplete") == "new-password"
        assert "3" in page.locator("#aiu-unsaved").inner_text() or "mục" in page.locator("#aiu-unsaved").inner_text()
        page.click("#aiu-save")
        page.wait_for_function("() => document.querySelector('#aiu-anthropic-key').value === ''")
        page.wait_for_function("() => document.querySelector('#aiu-anthropic-keyhint').innerText.includes('cdef')")
        puts = c.calls("PUT", "/api/ai/settings")
        assert len(puts) == 1
        body = puts[0][2]
        assert body["mode"] == "cloud_only" and body["anthropic"]["model"] == "claude-sonnet-5-5"
        assert body["anthropic"]["api_key"] == SECRET            # chỉ đi trong body request
        assert body["privacy"]["redact_secrets"] is True          # che secret là bắt buộc
        # sau khi lưu: ô key rỗng, không còn dấu vết của key ở DOM / storage / text hiển thị
        dump = page.evaluate("""() => JSON.stringify({
            ls: Object.entries(localStorage), ss: Object.entries(sessionStorage),
            html: document.documentElement.outerHTML,
            inputs: [...document.querySelectorAll('input,textarea,select')].map(e => e.value),
            toasts: document.getElementById('toast-stack') ? document.getElementById('toast-stack').innerText : ''
        })""")
        assert SECRET not in dump and SECRET[-12:] not in dump
        assert "…" + SECRET[-4:] in page.locator("#aiu-anthropic-keyhint").inner_text()   # chỉ 4 ký tự cuối (từ server)
        assert "Đã lưu" in page.locator("#aiu-anthropic-keyhint").inner_text()
    finally:
        ctx.close()


def test_cloud_test_uses_unsaved_form_values_without_saving(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.click('[data-prov="bedrock"]')
        page.select_option("#aiu-bedrock-auth", "bedrock_api_key")
        page.fill("#aiu-bedrock-region", "ap-southeast-1")
        page.fill("#aiu-bedrock-key", SECRET2)
        c.test_result = {"ok": True, "provider": "bedrock", "model": "anthropic.claude-opus-5-5", "latency_ms": 640, "tools": True, "json": True, "code": "VALID"}
        page.click("#aiu-cloud-test")
        page.wait_for_selector("#aiu-cloud-res.ok")
        txt = page.locator("#aiu-cloud-res").inner_text()
        assert "640 ms" in txt and "tools ✓" in txt and "JSON ✓" in txt
        tests = c.calls("POST", "/api/ai/test")
        assert len(tests) == 1
        b = tests[0][2]
        assert b["provider"] == "bedrock" and b["bedrock"]["region"] == "ap-southeast-1" and b["bedrock"]["auth_mode"] == "bedrock_api_key"
        assert b["bedrock"]["api_key"] == SECRET2                 # giá trị CHƯA LƯU được test
        assert c.calls("PUT") == []                               # test không lưu gì
        assert SECRET2 not in txt
        # lỗi: chỉ hiện mã chuẩn hoá, không hiện text provider (kể cả khi server lỡ echo key)
        c.test_result = {"ok": False, "provider": "bedrock", "code": "INVALID_KEY", "error": "Incorrect API key provided: " + SECRET2}
        page.click("#aiu-cloud-test")
        page.wait_for_selector("#aiu-cloud-res.err")
        err = page.locator("#aiu-cloud-res").inner_text()
        assert "401" in err and SECRET2 not in err and "Incorrect" not in err
        shot(page, "admin-test-connection-error")
    finally:
        ctx.close()


def test_ollama_capability_check_shows_tool_calling(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.fill("#aiu-ol-url", "http://192.168.1.50:11434")
        page.select_option("#aiu-ol-model", "deepseek-coder:6.7b")
        c.check_result = {"ok": True, "latency_ms": 90, "version": "0.12", "model_loaded": True, "tools": False, "json_ok": 3, "json_total": 3}
        page.click("#aiu-ol-test")
        page.wait_for_selector("#aiu-ol-checks li.x")
        checks = page.locator("#aiu-ol-checks").inner_text()
        assert "NOT supported" in checks or "KHÔNG hỗ trợ" in checks
        call = c.calls("POST", "/api/ai/ollama/check")[0][2]
        assert call == {"url": "http://192.168.1.50:11434", "model": "deepseek-coder:6.7b"}   # URL/model chưa lưu
        assert c.calls("PUT") == []
        # tools ✓ → hiện OK
        c.check_result = {"ok": True, "latency_ms": 182, "version": "0.12", "model_loaded": True, "tools": True, "json_ok": 2, "json_total": 3}
        page.click("#aiu-ol-test")
        page.wait_for_selector("#aiu-ol-checks li.ok")
        assert "1/3" in page.locator("#aiu-ol-checks").inner_text()
        shot(page, "admin-ollama-check")
    finally:
        ctx.close()


def test_missing_saved_model_is_flagged_not_replaced(base_url, browser):
    s = settings_fixture("ADMIN")
    s["ollama"]["model"] = "llama3.2-gone"
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN, settings=s)
    try:
        assert page.locator("#aiu-ol-model").input_value() == "llama3.2-gone"      # KHÔNG âm thầm đổi sang qwen2.5:7b
        assert page.locator("#aiu-ol-model-missing").is_visible()
        assert "llama3.2-gone" in page.locator("#aiu-ol-model-missing").inner_text()
        assert page.locator("#aiu-save").is_disabled()                              # chưa có thay đổi nào
    finally:
        ctx.close()


def test_inline_validation_blocks_save(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.fill("#aiu-h-lo", "90"); page.fill("#aiu-h-hi", "10")
        page.fill("#aiu-ol-url", "ftp://nope")
        page.click("#aiu-save")
        assert page.locator("#aiu-h-err").inner_text().strip() != ""
        assert page.locator("#aiu-ol-url-err").inner_text().strip() != ""
        assert c.calls("PUT") == []
        page.click("#aiu-discard")
        assert page.locator("#aiu-h-lo").input_value() == "15" and page.locator("#aiu-save").is_disabled()
    finally:
        ctx.close()


def test_admin_policy_and_usage_render_without_key_material(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        page.wait_for_selector("#aiu-usage tr >> nth=2")
        usage = page.locator("#aiu-usage").inner_text()
        assert "1280" in usage and "17,40" in usage.replace(".", ",") or "17.40" in usage
        assert page.locator("#aiu-ukeys button[data-act=uk-revoke]").count() == 1
        page.select_option("#aiu-p-byok", "required")
        page.click("#aiu-save")
        page.wait_for_function("() => document.querySelector('#aiu-save').disabled")
        page.wait_for_selector("#toast-stack .toast")
        pol = c.calls("PUT", "/api/ai/settings")[0][2]["policy"]
        assert pol["byok"] == "required" and pol["org_quota"] == {"usd_per_user_month": 20, "rpm_per_user": 60}
        shot(page, "admin-policy")
    finally:
        ctx.close()


# ───────── ANALYST ─────────
def test_analyst_readonly_org_controls_but_can_manage_own_keys(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ANALYST, settings=settings_fixture("ANALYST"))
    try:
        assert page.locator("#aiu-ro").is_visible() and "mục 4" in page.locator("#aiu-ro").inner_text()
        for i in range(org_controls(page).count()):
            el = org_controls(page).nth(i)
            assert el.is_disabled() or not el.is_visible(), el.evaluate("e => e.outerHTML.slice(0,120)")   # không có nút bấm-rồi-403
        assert page.locator("#aiu-sec-policy").is_hidden() and page.locator("#aiu-savebar").is_hidden()
        assert page.locator("#aiu-pull-btn").is_disabled()
        # section 4 hoạt động
        assert page.locator("#aiu-sec-mine").is_visible()
        page.wait_for_selector("#aiu-mine-table tr[data-id]")
        assert page.locator("#aiu-mine-table tr[data-id]").count() == 2
        assert "mặc định" in page.locator("#aiu-mine-table").inner_text()
        assert "…9fA1" in page.locator("#aiu-mine-table").inner_text() and SECRET not in page.content()
        assert page.locator("#aiu-add-btn").is_enabled()
        page.click("#aiu-add-btn")
        page.select_option("#aiu-add-prov", "anthropic")
        page.fill("#aiu-add-model", "claude-sonnet-5-5")
        # token OAuth gói Claude.ai bị từ chối ở client, không có request
        page.fill("#aiu-add-key", "sk-ant-oat01-abcdefghijklmnop")
        page.click("#aiu-add-go")
        assert page.locator("#aiu-add-err").inner_text().strip() != ""
        assert c.calls("POST", "/api/me/ai-credentials") == [] and page.locator("#aiu-add-key").input_value() == ""
        # key hợp lệ → gửi 1 lần, ô key xoá ngay, không echo
        page.fill("#aiu-add-key", SECRET)
        page.click("#aiu-add-go")
        page.wait_for_selector("#aiu-mine-table tr[data-id] >> nth=2")
        post = c.calls("POST", "/api/me/ai-credentials")
        assert len(post) == 1 and post[0][2]["secret"] == SECRET and post[0][2]["provider"] == "anthropic"
        assert page.locator("#aiu-add-key").input_value() == ""
        dump = page.evaluate("() => JSON.stringify([document.documentElement.outerHTML, Object.entries(localStorage), [...document.querySelectorAll('input')].map(e => e.value)])")
        assert SECRET not in dump
        assert "…" + SECRET[-4:] in page.locator("#aiu-mine-table").inner_text()
        # test 1 khoá & xoá
        page.click('#aiu-mine-table tr[data-id="c2"] [data-act=c-test]')
        page.wait_for_function("() => document.querySelector('#aiu-mine-msg').textContent.includes('✓')")
        page.once("dialog", lambda d: d.accept())
        page.click('#aiu-mine-table tr[data-id="c2"] [data-act=c-del]')
        page.wait_for_selector('#aiu-mine-table tr[data-id="c2"]', state="detached")
        # rotate: nhập key mới → PUT secret, ô xoá
        page.click('#aiu-mine-table tr[data-id="c1"] [data-act=c-rot]')
        page.fill("#aiu-rot-key", SECRET2)
        page.click('[data-act=c-rot-go]')
        page.wait_for_function("() => !document.querySelector('#aiu-rot-key')")
        put = c.calls("PUT", "/api/me/ai-credentials/c1/secret")
        assert put and put[0][2] == {"secret": SECRET2}
        assert SECRET2 not in page.evaluate("() => document.documentElement.outerHTML")
        # không một request admin nào bị gửi bởi analyst
        assert c.calls("PUT", "/api/ai/settings") == [] and c.calls("POST", "/api/ai/test") == [] and c.calls(None, "/api/ai/credentials") == [] and c.calls(None, "/api/ai/usage") == []
        shot(page, "analyst-light-vi")
    finally:
        ctx.close()


# ───────── VIEWER ─────────
def test_viewer_readonly_and_no_personal_keys(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.VIEWER, settings=settings_fixture("VIEWER"))
    try:
        assert page.locator("#aiu-ro").is_visible() and "mục 4" not in page.locator("#aiu-ro").inner_text()
        assert page.locator("#aiu-sec-mine").is_hidden() and page.locator("#aiu-sec-policy").is_hidden() and page.locator("#aiu-savebar").is_hidden()
        for i in range(org_controls(page).count()):
            el = org_controls(page).nth(i)
            assert el.is_disabled() or not el.is_visible()
        assert page.locator("#aiu-status .aiu-pill").count() == 3          # không có pill "Khoá của bạn"
        page.wait_for_timeout(400)
        assert c.calls(None, "/api/me/ai-credentials") == []                # VIEWER không gọi API khoá cá nhân (sẽ 403)
        shot(page, "viewer-light-vi")
    finally:
        ctx.close()


# ───────── bridge (backend cũ, chưa có /api/ai/settings) ─────────
def test_bridge_mode_keeps_legacy_tabs_and_never_fakes_unsaved_test(base_url, browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, locale="vi-VN")
    page = ctx.new_page()
    log = []

    def spy(route):
        req = route.request
        log.append((req.method, req.url.split("//", 1)[1].split("/", 1)[1]))
        route.fallback()
    page.route("**/api/ai/test", spy)
    page.route("**/api/ai/settings", lambda r: r.fulfill(status=404, content_type="application/json", body='{"detail":"Not Found"}'))
    page.route("**/api/me/ai-credentials**", lambda r: r.fulfill(status=404, content_type="application/json", body='{"detail":"Not Found"}'))
    email, _ = make_user(UserRole.ADMIN)
    try:
        _login(page, base_url, email)
        page.wait_for_selector("#user-chip", state="visible", timeout=15000)
        page.evaluate("navigate('settings')")
        page.wait_for_selector("#aiu-bridge:not(.aiu-hide)", timeout=15000)
        assert page.locator("#st-tab-ollama").is_visible() and page.locator("#st-tab-ai-legacy").is_visible()   # 2 tab cũ còn truy cập được
        page.click("#st-tab-ai-legacy"); assert page.locator("#st-ai-legacy").is_visible()
        page.click("#st-tab-ai")
        assert page.locator("#aiu-mine-unavail").is_visible() and page.locator("#aiu-policy-unavail").is_visible()   # không giả thành công
        assert page.locator("#aiu-add-btn").is_disabled() and page.locator("#aiu-p-byok").is_disabled()
        # form đã sửa → test KHÔNG gọi backend (backend chỉ test được cấu hình đã lưu) và không báo thành công
        page.click('#aiu-modes [data-mode="cloud_only"]')
        page.select_option("#aiu-anthropic-auth", "environment")
        page.fill("#aiu-anthropic-model", "claude-sonnet-5-5")
        page.click("#aiu-cloud-test")
        assert "ĐÃ LƯU" in page.locator("#aiu-cloud-res").inner_text()
        assert "ok" not in (page.locator("#aiu-cloud-res").get_attribute("class") or "").split()
        assert log == []
        shot(page, "bridge-mode")
    finally:
        ctx.close()


# ───────── i18n / theme / mobile / deep links ─────────
def test_language_switch_vi_en_and_persistence(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        assert "Nơi xử lý AI" in page.locator("#aiu-sec-mode h3").inner_text()      # VI mặc định
        page.fill("#aiu-h-lo", "20")                                                  # sửa dở → đổi ngôn ngữ không mất
        page.click('#aiu-lang [data-v="en"]')
        page.wait_for_function("() => document.querySelector('#aiu-sec-mode h3').innerText.includes('Where AI runs')")
        assert page.locator("#aiu-h-lo").input_value() == "20"
        assert "unsaved" in page.locator("#aiu-unsaved").inner_text()
        assert page.evaluate("localStorage.getItem('vg-ai-lang')") == "en"
        assert "Hybrid (recommended)" in page.locator("#aiu-modes").inner_text()
        shot(page, "admin-light-en")
        page.reload(); page.wait_for_selector("#user-chip", state="visible"); page.evaluate("navigate('settings')")
        page.wait_for_function("() => document.querySelector('#aiu-sec-mode h3') && document.querySelector('#aiu-sec-mode h3').innerText.includes('Where AI runs')")
        # khoá i18n thiếu → rơi về VI
        assert page.evaluate("document.querySelector('#st-ai').lang") == "en"
    finally:
        ctx.close()


def test_dark_theme_and_mobile_390_no_horizontal_overflow(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN, viewport={"width": 390, "height": 844}, theme="dark")
    try:
        assert page.evaluate("document.documentElement.dataset.theme") == "dark"
        for mode in ("hybrid", "cloud_only", "local_only"):
            page.evaluate("m => document.querySelector(`#aiu-modes [data-mode=${m}]`).click()", mode)
            over = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
            assert over <= 1, f"overflow {over}px ở mode {mode}"
        page.evaluate("document.querySelector('#aiu-modes [data-mode=hybrid]').click()")
        shot(page, "admin-dark-390-vi")
        # mobile: bảng "Khoá của tôi" cuộn ngang trong thẻ, không làm vỡ trang
        assert page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth") <= 1
    finally:
        ctx.close()
    ctx, page, c = open_ai(browser, base_url, UserRole.ANALYST, viewport={"width": 390, "height": 844}, theme="light", lang="en", settings=settings_fixture("ANALYST"))
    try:
        page.wait_for_selector("#aiu-mine-table tr[data-id]")
        assert page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth") <= 1
        shot(page, "analyst-light-390-en")
    finally:
        ctx.close()


def test_old_anchors_redirect_to_new_ones(base_url, browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, locale="vi-VN")
    page = ctx.new_page(); Contract(page)
    email, _ = make_user(UserRole.ADMIN)
    try:
        _login(page, base_url, email)
        page.goto(base_url + "/#st-ollama")
        page.wait_for_selector("#aiu-sec-ollama", state="visible", timeout=15000)
        page.wait_for_function("() => location.hash === '#ollama'")
        assert page.locator("#page-settings").evaluate("e => e.classList.contains('active')")
        assert page.locator("#st-ai").is_visible()
        page.evaluate("location.hash = '#st-ai'")
        page.wait_for_function("() => location.hash === '#mode'")
    finally:
        ctx.close()


def test_cowork_row_in_hybrid_rules_is_selectable_default_local(base_url, browser):
    ctx, page, c = open_ai(browser, base_url, UserRole.ADMIN)
    try:
        assert page.locator("#aiu-route-cw").input_value() == "local"
        assert page.locator("#aiu-p-cwcloud").count() == 0                       # không có toggle riêng cho Co-work
        page.select_option("#aiu-route-cw", "cloud")
        page.click("#aiu-save")
        page.wait_for_selector("#toast-stack .toast")
        assert c.calls("PUT", "/api/ai/settings")[0][2]["routing"] == {"coworker": "cloud"}
    finally:
        ctx.close()
