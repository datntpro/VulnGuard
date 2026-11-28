"""E2E (Chromium headless): dòng trạng thái route của Co-work (AI PR-5b, kế hoạch §4.11.5/§4.11.6) trên BACKEND THẬT.

Trình duyệt nói chuyện với app FastAPI thật (đăng nhập ADMIN, /api/coworker/agent/route-preview, /conversations/{id}/route,
/conversations/{id}/step). Chỉ thay ở biên ngoài: coworker_host (`_host_request`), Ollama (`LocalJsonBackend.chat`) và client SDK cloud
(không có mạng). Các trạng thái từ chối / hành động rủi ro được bơm bằng page.route() với đúng hình dạng JSON của server.

Ảnh chụp (light/dark × VI/EN) ghi ra thư mục COWORK_UI_SHOTS nếu biến môi trường này được đặt.
"""
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
from api.database import Base, SessionLocal, engine
from api.main import app
from api.services import ai_credentials as creds
from api.services import ai_policy, ai_usage
from tests._authutil import PASSWORD, make_user

ORG_KEY = "sk-ant-api03-ORGORGORGORGORG-0rg1"
USER_KEY = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA-9fA1"
SHOTS = os.environ.get("COWORKER_UI_SHOTS")
PAGE = "/static/agent.html"
CONSOLE = []


class Host:
    """coworker_host giả: một folder `f1` + workspace trong bộ nhớ."""

    def __init__(self):
        self.calls = []

    async def __call__(self, method, path, **kw):
        self.calls.append((method, path, kw))
        if path == "/folders":
            return {"folders": [{"id": "f1", "label": "demo", "path": "/w/demo"}]}
        if path == "/fs/file" and method == "POST":
            return {"ok": True}
        if path == "/fs/file":
            return {"content": "hello", "binary": False, "resolved": "a.txt", "symlink": False, "hardlink": False}
        return {}


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
        except Exception as e:
            pytest.skip(f"Chromium không khả dụng: {e}")
        yield b
        b.close()


@pytest.fixture(scope="module")
def admin(browser, base_url):
    email, uid = make_user(UserRole.ADMIN)
    ctx = browser.new_context(locale="vi-VN"); pg = ctx.new_page()
    pg.goto(base_url + "/login")
    pg.fill("#login-email", email); pg.fill("#login-password", PASSWORD)
    pg.click("#login-form button[type=submit]")
    pg.wait_for_url(lambda u: "/login" not in u, timeout=15000)
    state = ctx.storage_state(); ctx.close()
    return state, uid


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    monkeypatch.setenv("RUNTIME_SETTINGS_FILE", str(tmp_path / "rt.json"))
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for m in (AiUsageEvent, AiCredential):
        db.query(m).delete()
    db.commit()
    ai_usage.reset_rpm()
    from api.services import ai_config, runtime_settings
    runtime_settings.set_ollama(url="http://127.0.0.1:11434", model="qwen2.5:7b")
    ai_config.validate_and_save({"provider": "anthropic", "mode": "local_only", "anthropic": {"api_key": ORG_KEY},
                                 "hybrid": {"tasks": {"coworker": "local"}}})
    ai_policy.record_cloud_probe("anthropic", "claude-opus-5-5", True)
    host = Host()
    from api.routes import coworker, coworker_agent
    monkeypatch.setattr(coworker_agent, "_host_request", host)
    monkeypatch.setattr(coworker, "_host_request", host)
    yield db
    for m in (AiUsageEvent, AiCredential):
        db.query(m).delete()
    db.commit()
    db.close()


def _cfg(**kw):
    from api.services import ai_config
    return ai_config.validate_and_save(kw)


class Rec:
    def __init__(self, page):
        self.log = []
        page.on("request", self._on)

    def _on(self, req):
        from urllib.parse import urlparse
        u = urlparse(req.url)
        if u.path.startswith("/api/"):
            body = None
            if req.post_data:
                try:
                    body = json.loads(req.post_data)
                except Exception:
                    body = req.post_data
            self.log.append((req.method, u.path, body))

    def calls(self, method=None, contains=""):
        return [c for c in self.log if (method is None or c[0] == method) and contains in c[1]]


def open_page(browser, base, admin, *, lang="vi", theme="light", route=None, viewport=None):
    ctx = browser.new_context(storage_state=admin[0], locale="vi-VN" if lang == "vi" else "en-US",
                              viewport=viewport or {"width": 1280, "height": 800})
    ctx.add_init_script(f"try{{localStorage.setItem('vg-ai-lang','{lang}');localStorage.setItem('vg-theme','{theme}')}}catch(e){{}}")
    page = ctx.new_page()
    page.on('console', lambda m: CONSOLE.append(m.text))
    page.on('response', lambda r: CONSOLE.append((r.status, r.url)) if r.status>=400 else None)
    rec = Rec(page)
    if route:
        route(page)
    page.goto(base + PAGE)
    page.wait_for_function("() => document.querySelector('#routeText').textContent.length > 0", timeout=15000)
    return ctx, page, rec


def line(page):
    return page.locator("#routeText").inner_text()


def shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f"pr5b-{name}.png"), full_page=True)


def preview(page):
    return page.evaluate("async () => (await fetch('/api/coworker/agent/route-preview')).json()")


def fulfill(page, pattern, obj, status=200, method=None):
    def h(route):
        if method and route.request.method != method:
            return route.fallback()
        route.fulfill(status=status, content_type="application/json", body=json.dumps(obj))
    page.route(pattern, h)


# ───────── văn bản khớp route của server (backend thật) ─────────
def test_local_route_matches_server(browser, base_url, admin, env):
    ctx, page, _ = open_page(browser, base_url, admin, lang="vi")
    srv = preview(page)
    assert srv["state"] == "ok" and srv["route_kind"] == "local" and srv["data_leaves_machine"] is False
    assert line(page) == f"🏠 Chạy local · {srv['model']} — dữ liệu không rời máy này"
    assert page.locator("#routeLine").get_attribute("data-tone") == "local"
    shot(page, "local-light-vi")
    ctx.close()
    ctx, page, _ = open_page(browser, base_url, admin, lang="en")
    assert line(page) == f"🏠 Runs locally · {srv['model']} — data stays on this machine"
    ctx.close()


def test_cloud_own_key_shows_hint_and_leaves_machine(browser, base_url, admin, env):
    uid = admin[1]
    creds.create(env, scope="user", owner_user_id=uid, provider="anthropic", label="k", secret=USER_KEY,
                 params={"model": "claude-opus-5-5"}, created_by=uid, status="valid", is_default=True)
    env.commit()
    _cfg(mode="cloud_only")
    for lang, theme in (("vi", "light"), ("en", "dark"), ("vi", "dark"), ("en", "light")):
        ctx, page, _ = open_page(browser, base_url, admin, lang=lang, theme=theme)
        srv = preview(page)
        assert srv["route_kind"] == "cloud" and srv["key_scope"] == "user" and srv["key_hint"] == "…9fA1"
        txt = line(page)
        assert "Anthropic claude-opus-5-5" in txt and "…9fA1" in txt
        assert ("rời máy này" if lang == "vi" else "leave this machine") in txt        # cloud LUÔN có câu "rời máy"
        assert page.locator("#routeLine").get_attribute("data-tone") == "cloud"
        assert USER_KEY not in page.content() and ORG_KEY not in page.content()
        shot(page, f"cloud-{theme}-{lang}")
        ctx.close()


def test_cloud_org_key_has_no_hint(browser, base_url, admin, env):
    creds.migrate_org_config(env)
    env.commit()
    _cfg(mode="cloud_only")
    ctx, page, _ = open_page(browser, base_url, admin, lang="en")
    srv = preview(page)
    assert srv["route_kind"] == "cloud" and srv["key_scope"] == "org" and srv["key_hint"] is None
    txt = line(page)
    assert "organisation key" in txt and "leave this machine" in txt and "…" not in txt.split("(")[1].split(")")[0]
    assert "your key" not in txt and ORG_KEY[-4:] not in txt
    ctx.close()


def test_no_credential_refusal_real(browser, base_url, admin, env):
    _cfg(mode="cloud_only", policy={"fallback_to_org": False})
    ctx, page, _ = open_page(browser, base_url, admin, lang="en")
    srv = preview(page)
    assert srv["state"] == "refused" and srv["code"] == "AI_NO_CREDENTIAL"
    assert line(page) == "No AI key — add one in Settings › AI › My AI keys"
    assert page.locator("#routeLine").get_attribute("data-tone") == "refused"
    ctx.close()


def test_hybrid_default_local_and_cloud_row_follow_server(browser, base_url, admin, env):
    creds.migrate_org_config(env)
    env.commit()
    _cfg(mode="hybrid", hybrid={"tasks": {"coworker": "local"}})
    ctx, page, _ = open_page(browser, base_url, admin, lang="en")
    assert "Runs locally" in line(page); ctx.close()
    _cfg(mode="hybrid", hybrid={"tasks": {"coworker": "cloud"}})
    ctx, page, _ = open_page(browser, base_url, admin, lang="en")
    assert "Runs in the cloud" in line(page); ctx.close()


# ───────── mọi trạng thái từ chối / đổi cài đặt (JSON đúng hình dạng server) ─────────
REFUSALS = {
    "AI_ROUTE_CHANGED": ("Settings changed to Local — start a new conversation", "Cài đặt đã đổi sang Local — hãy bắt đầu hội thoại mới"),
    "AI_NO_CREDENTIAL": ("No AI key — add one in Settings › AI › My AI keys", "Chưa có khoá AI — thêm tại Settings › AI › Khoá AI của tôi"),
    "AI_CRED_REVOKED": ("This conversation's AI key was revoked — start a new conversation", "Khoá AI của hội thoại đã bị thu hồi — hãy bắt đầu hội thoại mới"),
    "AI_QUOTA": ("AI quota exhausted — start a new conversation or contact an administrator", "Đã hết hạn mức AI — hãy bắt đầu hội thoại mới hoặc liên hệ quản trị viên"),
    "AI_NOT_ALLOWED": ("AI policy does not allow this model — see Settings › AI", "Chính sách AI không cho phép model này — xem Settings › AI"),
    "AI_CLOUD_NO_TOOLS": ("The cloud model has not passed the tool-calling check — see Settings › AI", "Model cloud chưa qua kiểm tra tool-calling — xem Settings › AI"),
}


@pytest.mark.parametrize("code", sorted(REFUSALS))
@pytest.mark.parametrize("lang", ["en", "vi"])
def test_each_refusal_text(browser, base_url, admin, env, code, lang):
    body = {"state": "refused", "code": code, "message_key": "x", "route_kind": "cloud", "provider": "anthropic",
            "model": "claude-opus-5-5", "data_leaves_machine": True, "pinned": True, "settings_route": "local", "mode": "local_only"}
    ctx, page, _ = open_page(browser, base_url, admin, lang=lang, route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    suffix = {"en": " · This conversation ran in the cloud — content already sent left this machine",
              "vi": " · Hội thoại này đã chạy trên cloud — nội dung đã gửi đã rời máy này"}[lang]
    assert line(page) == REFUSALS[code][0 if lang == "en" else 1] + suffix       # đã ghim cloud → vẫn nói dữ liệu đã rời máy
    assert page.locator("#routeLine").get_attribute("data-tone") == "refused"
    if code == "AI_ROUTE_CHANGED":
        shot(page, f"refused-light-{lang}")
    ctx.close()


def test_pinned_local_after_settings_cloud_note(browser, base_url, admin, env):
    body = {"state": "ok", "route_kind": "local", "provider": "ollama", "model": "qwen2.5:7b", "key_scope": None, "key_hint": None,
            "data_leaves_machine": False, "pinned": True, "settings_route": "cloud", "settings_changed": True, "mode": "cloud_only"}
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    assert line(page) == "🏠 Runs locally · qwen2.5:7b — data stays on this machine · Settings changed: new conversations run on Cloud"
    ctx.close()


def test_server_text_is_never_rendered(browser, base_url, admin, env):
    body = {"state": "refused", "code": "<img src=x onerror=alert(1)>", "message_key": "<b>LEAK</b>", "detail": "sk-ant-LEAK"}
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    html = page.locator("#routeLine").inner_html()
    assert "LEAK" not in html and "<img" not in html and "onerror" not in html
    ctx.close()
    cloud = {"state": "ok", "route_kind": "cloud", "provider": "anthropic", "model": "<i>m</i>", "key_scope": "user", "key_hint": "…9fA1"}
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", cloud))
    assert page.locator("#routeLine i").count() == 0                       # textContent, không phải HTML
    ctx.close()


def test_no_control_changes_the_route_and_links_to_settings(browser, base_url, admin, env):
    ctx, page, rec = open_page(browser, base_url, admin)
    assert page.locator("#routeLine input, #routeLine select, #routeLine button, #routeLine textarea").count() == 0
    assert page.locator("#routeLine a").count() == 1 and page.locator("#routeLine a").get_attribute("href") == "/#settings-ai"
    assert page.locator("#routeLine a").inner_text() == "Settings › AI"
    # không có picker model/provider hay toggle cloud ở bất cứ đâu trong Co-work
    assert page.locator("select").count() == 2                              # chỉ folder + skill (có sẵn)
    assert {c[1] for c in rec.log if c[0] != "GET"} == set()                # mở trang không ghi gì
    ctx.close()


def test_settings_link_opens_ai_settings(browser, base_url, admin, env):
    ctx, page, _ = open_page(browser, base_url, admin)
    page.click("#routeLink")
    page.wait_for_selector("#page-settings.active", timeout=15000)
    page.wait_for_selector("#st-ai", state="visible", timeout=15000)
    ctx.close()


# ───────── Co-work dùng endpoint step của server (không gửi lịch sử) ─────────
def _fake_local_chat(monkeypatch, script):
    from api.routes import coworker_agent
    seq = list(script)

    async def fake_chat(self, messages, skill_body=None):
        return json.dumps(seq.pop(0)), "qwen"
    monkeypatch.setattr(coworker_agent.LocalJsonBackend, "chat", fake_chat)


def test_ui_uses_conversation_step_and_never_sends_history(browser, base_url, admin, env, monkeypatch):
    _fake_local_chat(monkeypatch, [{"thought": "t", "action": "write_file", "args": {"path": "a.txt", "content": "x"}},
                                   {"thought": "t", "action": "final", "args": {"answer": "xong"}}])
    ctx, page, rec = open_page(browser, base_url, admin)
    page.wait_for_function("() => document.querySelector('#folderSel').value === 'f1'")
    page.select_option("#skillSel", "")                                    # không auto-route skill (không tiêu thụ kịch bản)
    page.fill("#input", "ghi file a.txt")
    page.click("#send")
    try:
        page.wait_for_selector(".confirm", timeout=15000)
    except Exception:
        raise AssertionError(page.locator("#log").inner_text() + repr(rec.log[-6:]) + repr(CONSOLE))
    # write_file KHÔNG tự chạy
    assert page.locator("#approveBtn").is_enabled()                        # pending thường: không cần xác nhận thêm
    page.click("#approveBtn")
    page.wait_for_selector(".msg.answer", timeout=15000)
    assert "xong" in page.locator(".msg.answer").last.inner_text()
    steps = rec.calls("POST", "/step")
    assert steps and all("/conversations/" in c[1] and c[1].endswith("/step") for c in steps)
    assert not [c for c in rec.log if c[1] == "/api/coworker/agent/step"]   # không còn dùng /step stateless cũ
    for _, _, body in steps:
        assert set(body) <= {"message", "approve", "ack", "explicit", "auto", "reject", "folder_id", "skill_id"}
        assert "messages" not in body and "approved" not in body
    assert steps[0][2]["message"] == "ghi file a.txt"
    appr = [b for _, _, b in steps if b.get("approve")][0]
    assert appr["ack"] and appr.get("auto") in (None, False)
    # dòng trạng thái được làm mới theo route của hội thoại
    assert rec.calls("GET", "/route") and "Chạy local" in line(page)
    ctx.close()


def test_reject_sends_reject_pending_id(browser, base_url, admin, env, monkeypatch):
    _fake_local_chat(monkeypatch, [{"thought": "t", "action": "exec", "args": {"command": "ls"}},
                                   {"thought": "t", "action": "final", "args": {"answer": "ok"}}])
    ctx, page, rec = open_page(browser, base_url, admin)
    page.wait_for_function("() => document.querySelector('#folderSel').value === 'f1'")
    page.select_option("#skillSel", "")
    page.fill("#input", "chạy ls"); page.click("#send")
    page.wait_for_selector(".confirm", timeout=15000)
    page.click("#rejectBtn")
    page.wait_for_selector(".msg.answer", timeout=15000)
    assert [b for _, _, b in rec.calls("POST", "/step") if b.get("reject")]
    ctx.close()


def _step_mock(page, pending, status="awaiting_confirmation"):
    page.route("**/conversations/*/step", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps({"status": status, "pending": pending, "route_kind": "cloud"})))


RISKY = {"id": "p1", "action": "read_file", "args": {"path": ".env"}, "kind": "sensitive_read", "confirm_token": "tok1",
         "requires_explicit": True, "expires_in": 600, "warning": {"reason": "sensitive_path", "suspicious": True},
         "preview": {"kind": "sensitive_read", "path": ".env", "reason": "sensitive_path"}}
PLAIN = {"id": "p2", "action": "exec", "args": {"command": "ls"}, "kind": "side_effect", "confirm_token": "tok2",
         "requires_explicit": False, "expires_in": 600, "warning": None, "preview": {"kind": "exec", "command": "ls"}}


def test_risky_pending_disables_auto_approve_and_needs_explicit_ack(browser, base_url, admin, env):
    ctx, page, rec = open_page(browser, base_url, admin, lang="en", route=lambda p: _step_mock(p, RISKY))
    page.wait_for_function("() => document.querySelector('#folderSel').value === 'f1'")
    page.check("#autoApprove")                                              # người dùng ĐÃ bật tự duyệt
    page.fill("#input", "đọc .env"); page.click("#send")
    page.wait_for_selector(".confirm.risky", timeout=15000)
    assert page.locator("#autoApprove").is_disabled()                       # affordance bị tắt
    assert "disabled for this action" in page.locator(".confirm.risky .risk").inner_text()
    assert page.locator("#approveBtn").is_disabled()                        # chưa tick xác nhận
    assert not [b for _, _, b in rec.calls("POST", "/step") if b.get("approve")]   # KHÔNG tự duyệt
    shot(page, "risky-light-en")
    page.check("#riskAck")
    assert page.locator("#approveBtn").is_enabled()
    page.click("#approveBtn")
    page.wait_for_function("() => !document.querySelector('.confirm')")
    appr = [b for _, _, b in rec.calls("POST", "/step") if b.get("approve")][0]
    assert appr == {"folder_id": "f1", "skill_id": None, "approve": "p1", "ack": "tok1", "explicit": True}
    ctx.close()


def test_auto_approve_still_works_for_plain_pending(browser, base_url, admin, env):
    state = {"n": 0}

    def route(page):
        def h(r):
            state["n"] += 1
            body = {"status": "awaiting_confirmation", "pending": PLAIN} if state["n"] == 1 else {"status": "done", "answer": "ok"}
            r.fulfill(status=200, content_type="application/json", body=json.dumps(body))
        page.route("**/conversations/*/step", h)
    ctx, page, rec = open_page(browser, base_url, admin, route=route)
    page.wait_for_function("() => document.querySelector('#folderSel').value === 'f1'")
    page.check("#autoApprove")
    page.fill("#input", "chạy ls"); page.click("#send")
    page.wait_for_function("() => document.querySelector('#send').disabled === false", timeout=15000)
    appr = [b for _, _, b in rec.calls("POST", "/step") if b.get("approve")]
    assert appr and appr[0]["approve"] == "p2" and appr[0]["ack"] == "tok2" and appr[0]["auto"] is True
    assert page.locator(".confirm").count() == 0
    ctx.close()


def test_refusal_on_step_refreshes_status_line(browser, base_url, admin, env):
    def route(page):
        page.route("**/conversations/*/step", lambda r: r.fulfill(
            status=409, content_type="application/json", body=json.dumps({"detail": {"code": "AI_ROUTE_CHANGED", "message_key": "k"}, "code": "AI_ROUTE_CHANGED"})))
        fulfill(page, "**/conversations/*/route", {"state": "refused", "code": "AI_ROUTE_CHANGED", "route_kind": "cloud"})
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=route)
    page.wait_for_function("() => document.querySelector('#folderSel').value === 'f1'")
    page.fill("#input", "hi"); page.click("#send")
    page.wait_for_function("() => document.querySelector('#routeText').textContent.startsWith('Settings changed to Local')", timeout=15000)
    assert page.locator("#send").is_enabled()
    ctx.close()


def test_mobile_width_status_line_fits(browser, base_url, admin, env):
    creds.migrate_org_config(env)
    env.commit()
    _cfg(mode="cloud_only")
    ctx, page, _ = open_page(browser, base_url, admin, lang="vi", viewport={"width": 390, "height": 800})
    # (select skill có sẵn từ trước tự nó rộng hơn 390px — không thuộc PR này; chỉ kiểm dòng trạng thái)
    assert page.evaluate("document.querySelector('#routeLine').getBoundingClientRect().right <= window.innerWidth")
    assert page.evaluate("document.querySelector('#routeLine').scrollWidth <= document.querySelector('#routeLine').clientWidth + 1")
    shot(page, "cloud-390-vi")
    ctx.close()


def test_refusal_without_cloud_pin_has_no_leave_text(browser, base_url, admin, env):
    body = {"state": "refused", "code": "AI_NO_CREDENTIAL", "route_kind": None, "data_leaves_machine": False}
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    assert line(page) == REFUSALS["AI_NO_CREDENTIAL"][0]
    ctx.close()


def _lum(rgb):
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(page):
    """Tỉ lệ tương phản (WCAG) giữa màu chữ thật và màu nền thật của #routeText (qua canvas để quy đổi mọi cú pháp màu)."""
    rgbs = page.evaluate("""() => {
        const toRgb = (c) => { const x = document.createElement('canvas').getContext('2d'); x.fillStyle = '#000'; x.fillStyle = c; x.fillRect(0,0,1,1);
          const d = x.getImageData(0,0,1,1).data; return [d[0], d[1], d[2]]; };
        let bg = null; for (let e = document.querySelector('#routeText'); e && !bg; e = e.parentElement) {
          const c = getComputedStyle(e).backgroundColor; if (c && !/rgba\(.*, 0\)|transparent/.test(c)) bg = c; }
        return [toRgb(getComputedStyle(document.querySelector('#routeText')).color), toRgb(bg || getComputedStyle(document.body).backgroundColor)];
    }""")
    a, b = _lum(rgbs[0]), _lum(rgbs[1])
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("tone", ["cloud", "refused"])
def test_warning_text_meets_wcag_aa(browser, base_url, admin, env, theme, tone):
    body = ({"state": "ok", "route_kind": "cloud", "provider": "anthropic", "model": "claude-opus-5-5", "key_scope": "org", "key_hint": None}
            if tone == "cloud" else {"state": "refused", "code": "AI_QUOTA", "route_kind": "cloud"})
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", theme=theme, route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    assert page.locator("#routeLine").get_attribute("data-tone") == tone
    assert _contrast(page) >= 4.5, _contrast(page)
    ctx.close()


def test_auto_approve_disabled_on_cloud_route(browser, base_url, admin, env):
    body = {"state": "ok", "route_kind": "cloud", "provider": "anthropic", "model": "claude-opus-5-5",
            "data_leaves_machine": True, "pinned": False, "mode": "cloud_only"}
    ctx, page, _ = open_page(browser, base_url, admin, lang="en", route=lambda p: fulfill(p, "**/api/coworker/agent/route-preview", body))
    page.wait_for_function("() => document.querySelector('#autoApprove').disabled === true", timeout=15000)
    assert "cloud" in page.locator("#autoApprove").get_attribute("title").lower()
    ctx.close()
