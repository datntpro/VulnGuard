"""Static regression tests: no unescaped data in innerHTML sinks (PR-D)."""
import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
INDEX = (WEB / "index.html").read_text(encoding="utf-8")
AGENT = (WEB / "agent.html").read_text(encoding="utf-8")


def test_index_no_raw_error_message():
    assert not re.findall(r"\$\{\s*e\.message\s*\}", INDEX)


def test_agent_no_raw_error_message():
    assert not re.findall(r"\$\{\s*e\.message\s*\}", AGENT)


def test_index_sinks_are_escaped():
    pat = re.compile(r"\$\{\s*(result\.message|v\.title|f\.label|f\.path|f\.id|m\.name"
                     r"|summary\.approve_message|v\.priority_reason|v\.severity_original)\s*(\}|\.slice|\|\|)")
    assert not pat.findall(INDEX)


def test_deletemodel_uses_jsstr():
    assert "deleteModel('${m.name}')" not in INDEX
    assert "deleteModel('${jsStr(m.name)}')" in INDEX


def test_agent_esc_escapes_quotes():
    m = re.search(r"function esc\(s\)[^\n]*", AGENT)
    assert m and "&quot;" in m.group(0) and "&#39;" in m.group(0)


# ── Extra static guards (PR-D follow-up: verifier findings) ─────────────────
def test_no_eschtml_inside_js_string_handlers():
    # escHtml() inside '…' in an on*="" handler is decoded by the HTML parser
    # back to ' before JS runs -> breakout. Must be jsStr().
    assert not re.findall(r"on\w+=\"[^\"]*'\$\{escHtml\(", INDEX)


def test_no_json_stringify_in_attribute():
    assert not re.findall(r"on\w+=\"[^\"]*\$\{JSON\.stringify\(", INDEX)


def test_no_concatenated_error_message_in_innerhtml():
    assert not re.findall(r"innerHTML\s*\+?=\s*['\"`][^;\n]*\+\s*e\.message", INDEX)


def test_vision_model_options_escaped():
    assert "<option value=\"${n}\"" not in INDEX
    assert "<option value=\"${cur}\"" not in INDEX
    assert "${n}</option>" not in INDEX


def test_cowork_breadcrumb_and_parent_escaped():
    assert "${cwState.currentPath || '/'}" not in INDEX
    assert "cwLoadTree('${cwState.currentPath" not in INDEX


def test_crawl_views_escaped():
    for raw in ("${e.method}", "${e.method||'GET'}", "${m}: ${n}",
                "${(e.query_params||[]).join", "${(e.body_params||[]).join"):
        assert raw not in INDEX, raw


# ── Headless-browser PoC test (skipped if Playwright/Chromium unavailable) ──
import pytest  # noqa: E402

PAYLOAD_IMG = "<img src=x onerror=pwn('img')>"
PAYLOAD_JS = "x');pwn('js');('"


def _browser_page():
    sync_api = pytest.importorskip("playwright.sync_api")
    pw = sync_api.sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:  # browser binary missing
        pw.stop()
        pytest.skip(f"chromium unavailable: {exc}")
    page = browser.new_page()
    page.route("**/*", lambda r: r.abort() if not r.request.url.startswith("file:") else r.continue_())
    page.add_init_script("window.__pwn=[];window.pwn=function(x){window.__pwn.push(x)};")
    page.goto((WEB / "index.html").as_uri())
    return pw, browser, page


def _mock(page, mapping_js):
    page.evaluate("(()=>{ const m = " + mapping_js + "; window.api = async function(path){ "
                  "for (const k in m) if (String(path).startsWith(k)) { if (m[k] && m[k].__throw) "
                  "throw new Error(m[k].__throw); return m[k]; } return []; }; })()")


def test_browser_poc_sinks_do_not_execute():
    pw, browser, page = _browser_page()
    try:
        evil_ep = {"method": PAYLOAD_IMG, "url": "http://t/", "path": "/",
                   "query_params": [PAYLOAD_IMG], "body_params": [PAYLOAD_IMG], "status_code": 200}
        _mock(page, "{"
              "'/api/knowledge/status': {__throw:" + repr(PAYLOAD_IMG) + "},"
              "'/api/ollama/vision-model': {installed:[" + repr(PAYLOAD_IMG) + "], vision_model:" + repr(PAYLOAD_IMG) + "},"
              "'/api/domains/crawls/': [" + __import__("json").dumps(evil_ep) + "],"
              "'/api/domains': [{id:'d1',name:" + repr(PAYLOAD_JS) + ",crawl_count:0}],"
              "'/api/docreview/documents': [{id:'x1',name:" + repr(PAYLOAD_JS) + ",versions:[]}],"
              "'/api/coworker/fs/tree': {entries:[]}"
              "}")
        page.evaluate("loadKnowledge()")
        page.evaluate("loadVisionModel()")
        page.evaluate("currentCrawlId='c1'; document.getElementById('endpoints-list') && loadEndpoints()")
        page.evaluate("loadDomains()")
        page.evaluate("loadDocReviews()")
        page.evaluate(f"cwState.folderId='f'; cwLoadTree({PAYLOAD_IMG!r})")
        page.evaluate(f"cwLoadTree({'a/' + PAYLOAD_JS!r})")
        page.evaluate("document.querySelectorAll('#cw-tree div[onclick]').forEach(b=>b.click())")
        page.evaluate("document.getElementById('domains-list').querySelectorAll('button').forEach(b=>{try{b.click()}catch(e){}})")
        page.evaluate("document.getElementById('docreview-list').querySelectorAll('button').forEach(b=>{try{b.click()}catch(e){}})")
        # ptCode "Xem thêm" button with hostile >1400 byte body
        page.evaluate("document.body.insertAdjacentHTML('beforeend', "
                      f"ptCode('><img src=x onerror=pwn(\"pt\")>' + 'A'.repeat(1500)))")
        page.wait_for_timeout(500)
        assert page.evaluate("window.__pwn") == []
    finally:
        browser.close()
        pw.stop()


def test_kb_status_and_kev_badge_escaped():
    for raw in ("${s.version || '?'}", "${s.built_at || '?'}", "${(s.sources || []).join(', ') || '?'}",
                "${s.update_interval_hours}", "`${k}: ${v}`", 'title="${t}"'):
        assert raw not in INDEX, raw
    assert 'title="${escHtml(t)}"' in INDEX
