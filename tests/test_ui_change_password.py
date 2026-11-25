"""E2E (Chromium headless): luồng đăng nhập lần đầu → ép đổi mật khẩu. Bỏ qua nếu thiếu Playwright/Chromium."""
import socket
import threading
import time

import pytest

pw_sync = pytest.importorskip("playwright.sync_api")

import uvicorn

from api.main import app
from tests._authutil import PASSWORD, make_user
from tests.test_change_password import _row

NEW = "Fresh-pass-2026"


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


def _login(page, base, email, password):
    page.goto(base + "/login")
    page.fill("#login-email", email)
    page.fill("#login-password", password)
    page.click("#login-form button[type=submit]")


def test_first_login_forced_change_flow(base_url, browser):
    email, _ = make_user(must_change_password=True)
    before = _row(email)
    ctx = browser.new_context()
    page = ctx.new_page()
    posts = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and "change-password" in r.url else None)

    _login(page, base_url, email, PASSWORD)
    page.wait_for_selector("#cp-cur", timeout=15000)
    assert page.locator("#cp-new").count() == 1 and page.locator("#cp-confirm").count() == 1

    # typo ở ô xác nhận → chặn phía client, không có request nào, DB không đổi
    page.fill("#cp-cur", PASSWORD); page.fill("#cp-new", NEW); page.fill("#cp-confirm", NEW + "x")
    page.click("#cp-go")
    assert "không khớp" in page.locator("#cp-msg").inner_text()
    page.wait_for_timeout(300)
    assert posts == []
    assert _row(email).password_hash == before.password_hash

    # mật khẩu yếu → hiện quy tắc
    page.fill("#cp-new", "aaaaaaaaaa"); page.fill("#cp-confirm", "aaaaaaaaaa")
    page.click("#cp-go")
    assert "3 trong 4 loại" in page.locator("#cp-msg").inner_text()
    assert posts == []

    # hợp lệ → reload, overlay biến mất, không còn lỗi cũ
    page.fill("#cp-new", NEW); page.fill("#cp-confirm", NEW)
    with page.expect_navigation(timeout=15000):
        page.click("#cp-go")
    page.wait_for_load_state("networkidle")
    assert page.locator("#force-cp-overlay").count() == 0
    assert "phải đổi mật khẩu" not in page.content()
    assert len(posts) == 1
    row = _row(email)
    assert row.must_change_password is False and row.token_version == (before.token_version or 0) + 1

    # điều hướng menu không bị đá về /login
    for nav in ("projects", "scans", "domains", "dashboard"):
        page.click(f"#nav-{nav}")
        page.wait_for_timeout(700)
        assert "/login" not in page.url, nav
    ctx.close()

    # mật khẩu cũ bị từ chối, mật khẩu mới vào được
    c_old = browser.new_context(); p_old = c_old.new_page()
    _login(p_old, base_url, email, PASSWORD)
    p_old.wait_for_timeout(2000)
    assert "/login" in p_old.url
    c_old.close()
    c_new = browser.new_context(); p_new = c_new.new_page()
    _login(p_new, base_url, email, NEW)
    p_new.wait_for_url(lambda u: "/login" not in u, timeout=15000)
    assert p_new.locator("#force-cp-overlay").count() == 0
    c_new.close()
