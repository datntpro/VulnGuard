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
    # Tab Ollama cũ đã bị xoá (PR-5); xoá model nay nằm ở web/ai-settings.js: không inline onclick, tên đi qua data-name + esc()
    import pathlib
    js = (pathlib.Path(__file__).resolve().parent.parent / "web" / "ai-settings.js").read_text(encoding="utf-8")
    assert "deleteModel('${" not in INDEX and "deleteModel('${" not in js
    assert 'data-act="ol-del" data-name="${esc(m.name)}"' in js


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
              "'/api/domains/crawls/': [" + __import__("json").dumps(evil_ep) + "],"
              "'/api/domains': [{id:'d1',name:" + repr(PAYLOAD_JS) + ",crawl_count:0}],"
              "'/api/docreview/documents': [{id:'x1',name:" + repr(PAYLOAD_JS) + ",versions:[]}],"
              "'/api/coworker/fs/tree': {entries:[]}"
              "}")
        page.evaluate("loadKnowledge()")
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
                "${s.update_interval_hours}", "map(([k, v]) => `${k}: ${v}`).join(' · ')", 'title="${t}"'):
        assert raw not in INDEX, raw
    assert 'title="${escHtml(t)}"' in INDEX


# ── P1-8: Phase-1 pentest UI sinks ──────────────────────────────────────────
def _fn(name):
    m = re.search(r"(?:async )?function %s\b.*?\n\}\n" % re.escape(name), INDEX, re.S)
    assert m, name
    return m.group(0)


def test_p18_confidence_badge_escaped_and_no_verified_tick():
    body = _fn("ptConfBadge")
    assert "escHtml(m[0])" in body
    assert "✓ Đã xác thực" not in INDEX          # dấu tick "verified" cũ đã bị thay bằng badge confidence
    assert "${ptConfBadge(f.confidence)}" in INDEX
    assert "${escHtml(f.validator)}" in INDEX


def test_p18_roe_card_escapes_every_dynamic_value():
    body = _fn("renderRoeCard")
    for raw in ("${e.emergency_contact", "${e.roe_note}", "${w.tz", "${w.start", "${w.end", "${set}", "${real}"):
        assert raw not in body, raw
    for esc in ("escHtml(e.emergency_contact", "escHtml(e.roe_note", "escHtml(w.tz", "escHtml(set)", "escHtml(real)"):
        assert esc in body, esc


def test_p18_window_row_escaped():
    body = _fn("emWindowRowHtml")
    for raw in ("${w.start", "${w.end", "${w.tz"):
        assert raw not in body, raw
    assert "escHtml(w.tz" in body


def test_p18_stop_reason_and_outcome_escaped():
    assert "escHtml(ptStopReason(r))" in INDEX
    assert "${ptStopReason(r)}" not in INDEX
    body = _fn("ptOutcomeBadge")
    assert "ptBadge(label, t)" in body             # ptBadge luôn escHtml


def test_p18_proxy_token_and_ca_url_escaped():
    assert "escHtml(ptState.proxySecret.token)" in INDEX
    assert "escHtml(ptState.proxySecret.username)" in INDEX
    assert "${ptState.proxySecret.token}" not in INDEX
    assert "escHtml(encodeURIComponent(ptState.curEngId))" in INDEX
    assert "/api/pentest/proxy/ca.crt" not in INDEX   # CA toàn cục đã bị gỡ (410)


def test_p18_degraded_and_roe_lock_present():
    assert "e.degraded_mode" in INDEX
    assert "Thu hồi uỷ quyền để sửa" in INDEX
    assert "setRoeLocked(!!(eng && eng.authorized))" in INDEX


# ── P1-8 follow-up (PR #61 verify) ──────────────────────────────────────────
def test_p18_stop_reason_reads_error_message_not_current_engagement():
    body = _fn("ptStopReason")
    assert "r.error_message" in body
    assert "ptState" not in body                 # không đoán từ engagement hiện tại
    assert "kill switch" in body                 # chỉ là mặc định khi error_message rỗng


def test_p18_viewer_hides_write_controls():
    assert "function canWrite()" in INDEX
    for needle in ("${canWrite() ? `<div class=\"flex\">", "authOk = e.authorized && !expired && canWrite()",
                   "${active && canWrite() ?", "${!canWrite() ? ''"):
        assert needle in INDEX, needle


def test_p18_proxy_token_cleared_after_copy_and_navigation():
    body = _fn("copyProxyToken")
    assert "ptState.proxySecret = null" in body
    assert "ptState.proxySecret = null;   // token chỉ hiện một lần" in INDEX   # openEngagement
    assert re.search(r"function navigate\(page\) \{\n  if \(page !== 'pentest-engagement'[^\n]*proxySecret = null", INDEX)


def test_p18_conf_badge_ignores_prototype_keys():
    assert "hasOwnProperty.call(PT_CONF, c)" in _fn("ptConfBadge") or "hasOwnProperty.call(PT_CONF, c)" in INDEX


# ── P2-17: Phase-2 pentest UI sinks ─────────────────────────────────────────
def test_p217_static_sinks_escaped():
    for name, needles in {
        "ptTaskNode": ("escHtml(t.title)", "escHtml(t.kind)", "escHtml(res.slice(0, 240))"),
        "renderApprovalContext": ("escHtml(typeof x === 'string'", "ptCode(c.source_excerpt"),
        "renderValidation": ("escHtml(v.details)", "escHtml(v.validator)", "escHtml(v.severity_cap)", "jsStr(poc.replay_traffic_id)"),
        "renderRuntimeCard": ("escHtml(j.last_error)", "escHtml(cp.seq)"),
        "renderEngagementGraph": ("escHtml(n.key)", "escHtml(n.kind)", "escHtml(label(e.src))", "escHtml(label(e.dst))"),
        "ptCvssBadge": ("Number(f.cvss_v4_score)",),
    }.items():
        body = _fn(name)
        for n in needles:
            assert n in body, (name, n)
    # định dạng báo cáo đi qua jsStr trong handler
    assert "ptDownloadReport('${jsStr(f)}', this)" in INDEX
    for raw in ("${t.title}", "${n.key}", "${v.details}", "${j.last_error}", "${c.source_excerpt}", "${f.cvss_v4_vector}", "${f.wstg_id}"):
        assert raw not in INDEX, raw


def test_p217_sse_uses_event_source_and_closes_on_terminal():
    body = _fn("ptStartStream")
    assert "new EventSource(" in body and "encodeURIComponent(id)" in body
    assert "es.close()" in body and "ptActive(d.status)" in body     # không nối lại vô hạn sau khi run kết thúc
    assert "ptEs.close()" in _fn("stopPentestPoll")


def test_p217_followups_static():
    # F1: CVSS/WSTG/ATT&CK nằm trong drawer pentest, KHÔNG trong drawer web-scan
    assert "wstg_id" in _fn("openPentestFindingDrawer") and "cvss_v4_vector" in _fn("openPentestFindingDrawer")
    for k in ("wstg_id", "cvss_v4_vector", "attack_technique"):
        assert k not in _fn("openFindingDrawer"), k
    # F2: menu báo cáo không còn absolute (không bị sidebar che)
    assert "position:absolute" not in _fn("renderReportMenu")
    # F3: toolbar dựng một lần, SSE chỉ vẽ lại #pt-run-dyn
    body = _fn("renderRunDetail")
    assert "pt-run-dyn" in body and "dyn.innerHTML = `" in body and "el.dataset.run !== String(r.id)" in body
    assert "ptEgressDenied" not in INDEX            # F5: không đoán từ output nữa


def test_p217_arch_toggle_admin_only_and_locked():
    assert "canAdmin() && !archSel.disabled" in INDEX
    assert "archSel.disabled = !!(eng && eng.authorized)" in INDEX


def test_p217_browser_hostile_values_do_not_execute():
    pw, browser, page = _browser_page()
    try:
        evil = PAYLOAD_IMG
        evil_js = PAYLOAD_JS
        import json as _json
        d = _json.dumps
        page.evaluate("window.canWrite = () => true")
        page.evaluate("document.body.insertAdjacentHTML('beforeend', '<div id=\"p217\"></div>')")
        # PTG: title/result/kind do target controlled; chu trình parent_id không được treo
        tasks = [{"id": "a", "parent_id": None, "title": evil, "kind": evil, "status": evil, "depends_on": [], "result": evil, "attempts": 2},
                 {"id": "b", "parent_id": "a", "title": evil_js, "kind": "scan", "status": "failed", "depends_on": ["a"], "result": {"x": evil}},
                 {"id": "c", "parent_id": None, "title": evil, "kind": "recon", "status": "failed", "depends_on": [], "result": evil},
                 {"id": "d", "parent_id": "e", "title": "cycle", "kind": "scan", "status": "pending"},
                 {"id": "e", "parent_id": "d", "title": "cycle", "kind": "scan", "status": "pending"}]
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"renderPtg({d(tasks)})"))
        rt = {"agent_arch": evil, "exec_backend": "sandbox", "egress_gateway": "enforced", "validators": evil, "worker_mode": evil,
              "degraded": True, "sandbox_configured": False,
              "job": {"status": evil, "attempts": 2, "lease_expired": True, "last_error": evil},
              "checkpoint": {"seq": evil, "created_at": evil}}
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"renderRuntimeCard({d(rt)})"))
        ctx = {"injection_signals": [evil, {"k": evil}], "source_excerpt": evil + "A" * 1500}
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"renderApprovalContext({d(ctx)})"))
        f = {"validation": {"status": evil, "validator": evil, "details": evil, "mode": evil, "severity_cap": evil, "repeats": evil},
             "poc": {"curl": evil, "steps": [evil], "replay_traffic_id": evil_js},
             "cvss_v4_score": 9.3, "cvss_v4_severity": evil}
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"renderValidation({d(f)})"))
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"ptCvssBadge({d(f)}) + ptValBadge({d(f['validation'])})"))
        # graph tab
        g = {"nodes": [{"id": "n1", "kind": evil, "key": evil, "confidence": 0.5, "in_scope": False},
                       {"id": "n2", "kind": "host", "key": evil_js, "confidence": None, "in_scope": True}],
             "edges": [{"id": "e1", "src": "n1", "dst": "n2", "rel": evil}, {"id": "e2", "src": evil, "dst": "zz", "rel": "x"}]}
        page.evaluate("document.getElementById('p217').insertAdjacentHTML('beforeend','<div id=\"pt-eng-graph-body\"></div>')")
        page.evaluate(f"ptState.graph = {d(g)}; ptState.graphKind = {d(evil)}; renderEngagementGraph()")
        # step timeline egress badge
        step = {"id": "s1", "step_number": 1, "tool_name": evil, "outcome": "blocked_policy", "output": "x " + evil, "thought": evil, "tool_input": {"u": evil}}
        den = {"count": 30, "recent": [{"id": "t1", "target": evil, "host": evil, "kind": evil, "reason": evil, "step": "s1", "created_at": evil}]}
        page.evaluate(f"ptState.runtime = {{egress_denied: {d(den)}}}")
        page.evaluate("html => document.getElementById('p217').insertAdjacentHTML('beforeend', html)", page.evaluate(f"renderStep({d(step)}) + renderEgressDenied(ptState.runtime)"))
        assert page.evaluate(f"ptEgressForStep({d(step)}).length") == 1
        # click mọi nút/handler được sinh ra (replay PoC, tải báo cáo…) — không được chạy mã tiêm vào
        page.evaluate("window.api = async () => ({status_code: 200, response_preview: '<img src=x onerror=pwn(\"rp\")>'}); "
                      "document.querySelectorAll('#p217 button[onclick]').forEach(b => { try { b.click() } catch (e) {} })")
        page.wait_for_timeout(500)
        assert page.evaluate("document.getElementById('p217').children.length") >= 6   # nội dung thực sự được render
        assert page.evaluate("window.__pwn") == []
        assert page.evaluate("document.querySelectorAll('#p217 img[src=\"x\"]').length") == 0   # không có thẻ <img> do payload tạo ra
    finally:
        browser.close()
        pw.stop()


def test_p217_sse_rerender_keeps_report_menu_state():
    pw, browser, page = _browser_page()
    try:
        page.evaluate("document.body.insertAdjacentHTML('beforeend', '<div id=\"pentest-run-content\"></div>')")
        page.evaluate("""(()=>{ window.canWrite = () => true;
          ptState.curRunId = 'r1'; ptState.curEng = null; ptState.steps = [{id:'s1', step_number: 1, tool_name:'t', outcome:'executed'}];
          ptState.findings = []; ptState.approvals = []; ptState.tasks = []; ptState.runtime = null;
          ptState.run = {id:'r1', run_number:1, goal:'g', targets:[], status:'RUNNING', mode:'GUIDED', progress:{}, summary:{}, steps_used:1, tokens_used:1};
          renderRunDetail(); })()""")
        page.evaluate("""(()=>{ const d = document.querySelector('.pt-report-menu'); d.open = true;
          document.getElementById('pt-rep-include').value = 'all';
          document.querySelector('details.pt-step').open = true; })()""")
        page.evaluate("ptState.steps.push({id:'s2', step_number: 2, tool_name:'u', outcome:'executed'}); renderRunDetail()")
        assert page.evaluate("document.querySelector('.pt-report-menu').open") is True
        assert page.evaluate("document.getElementById('pt-rep-include').value") == "all"
        assert page.evaluate("document.querySelectorAll('details.pt-step').length") == 2
        assert page.evaluate("document.querySelector('details.pt-step').open") is True
        # menu nằm trong luồng bình thường, không bị sidebar (position:fixed) che
        assert page.evaluate("getComputedStyle(document.querySelector('.pt-report-menu .card')).position") == "static"
    finally:
        browser.close()
        pw.stop()
