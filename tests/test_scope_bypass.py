"""Regression tests cho các lỗ hổng scope/an toàn của Pentest Agent (PoC B1-B4)."""
import asyncio

import pytest

from api.pentest_models import AutonomyMode
from scanner.pentest import scope, toolbelt
from scanner.pentest.gating import decide_action
from scanner.pentest.scope import check_target, canonicalize_target, ScopeError

def _run(coro):
    # loop riêng, không đụng event-loop policy (các test khác dùng get_event_loop())
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


ONE_IP = [{"type": "ip", "value": "172.18.0.2", "mode": "allow"}]
NET24 = [{"type": "cidr", "value": "10.1.0.0/24", "mode": "allow"}]
DOMAIN = [{"type": "domain", "value": "example.com", "include_subdomains": True, "mode": "allow"}]


# ───── B1: nmap quét cả CIDR khi scope chỉ có 1 IP ─────
@pytest.mark.parametrize("bad", [
    "172.18.0.2/28", "172.18.0.2/8", "172.18.0.0/24", "172.18.0.2/0",
    "172.18.0.2,172.18.0.3", "172.18.0.2 172.18.0.3", "172.18.0.1-5", "172.18.0.2-172.18.0.9",
    "172.18.0.*", "-iL/etc/passwd", "--script=x 172.18.0.2", "172.18.0.2\n10.0.0.1",
    "172.18.0.2/99", "2130706433", "0x7f000001", "127.1",
])
def test_b1_port_scan_rejects_non_single_target(bad):
    d, _ = decide_action(toolbelt.get_tool("port_scan") or _fake_nmap(), {"host": bad},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, ONE_IP)
    assert d in ("block_scope", "block_unavail")
    assert check_target(bad, ONE_IP)[0] is False


def _fake_nmap():
    t = toolbelt.get_tool("port_scan")
    return t


def test_b1_single_ip_still_ok():
    assert check_target("172.18.0.2", ONE_IP)[0]
    assert check_target("172.18.0.2/32", ONE_IP)[0]


def test_b1_cidr_must_be_subset_of_scope():
    assert check_target("10.1.0.0/25", NET24)[0]
    assert check_target("10.1.0.0/24", NET24)[0]
    assert check_target("10.1.0.0/23", NET24)[0] is False
    assert check_target("10.0.0.0/8", NET24)[0] is False
    # domain rule không bao giờ cho phép một dải
    assert check_target("10.1.0.0/25", DOMAIN)[0] is False


def test_b1_cidr_overlapping_deny_blocked():
    rules = NET24 + [{"type": "ip", "value": "10.1.0.9", "mode": "deny"}]
    assert check_target("10.1.0.0/25", rules)[0] is False
    assert check_target("10.1.0.128/25", rules)[0]


def test_b1_nmap_argv_uses_canonical_target(monkeypatch):
    seen = {}

    async def fake(argv, timeout):
        seen["argv"] = argv
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    _run(toolbelt._port_scan({"host": "Example.COM."}))
    assert seen["argv"][-2:] == ["--", "example.com"]
    out = _run(toolbelt._port_scan({"host": "10.0.0.1/8,--script=x"}))
    assert out["ran"] is False


@pytest.mark.parametrize("target,host", [
    ("HTTP://Example.COM:8080/a", "example.com"),
    ("bücher.example.com", "xn--bcher-kva.example.com"),
    ("example.com.", "example.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
])
def test_canonicalize(target, host):
    assert canonicalize_target(target)["host"] == host


@pytest.mark.parametrize("bad", ["", "  ", "http://user@example.com", "http://example.com\\@evil.com",
                                 "ftp://example.com", "http://[::1%eth0]/", "a b", "exa*mple.com"])
def test_canonicalize_rejects(bad):
    with pytest.raises(ScopeError):
        canonicalize_target(bad)


def test_unparsable_is_out_of_scope_fail_closed():
    assert check_target("http://exa mple.com", DOMAIN)[0] is False
    assert check_target(None, DOMAIN)[0] is False


def test_in_scope_usage_unchanged():
    assert check_target("https://example.com/x?y=1", DOMAIN)[0]
    assert check_target("api.example.com:8443", DOMAIN)[0]
    assert check_target("evil.com", DOMAIN)[0] is False
    assert check_target("http://example.com@evil.com/", DOMAIN)[0] is False


def test_agent_execute_fails_closed_on_scope_check_error(monkeypatch):
    from scanner.pentest.agent import PentestAgent
    monkeypatch.setattr(scope, "check_target_resolved", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ran = {"v": False}

    async def runner(i, c):
        ran["v"] = True
        return {}
    tool = toolbelt.Tool("t", None, "", {}, runner, target_keys=["host"])
    ag = PentestAgent.__new__(PentestAgent)
    ag.run_id = 1
    ag._scope_rules = ONE_IP
    out = _run(ag._execute(tool, {"host": "172.18.0.2"}))
    assert "BỊ CHẶN" in out and ran["v"] is False


# ───── B2: http_probe đi theo redirect ra ngoài scope ─────
import httpx  # noqa: E402

REDIR_RULES = [{"type": "ip", "value": "10.1.0.5", "mode": "allow"}]


def _probe(location, rules=REDIR_RULES, url="http://10.1.0.5/start", extra=None):
    """http_probe với transport giả: URL start trả 302 → location; ghi lại mọi request thật sự được gửi."""
    sent = []

    def handler(req: httpx.Request):
        sent.append(str(req.url))
        if req.url.path == "/start":
            return httpx.Response(302, headers=[(b"location", location.encode("utf-8"))], text="redir")
        return httpx.Response(200, text="<title>reached</title>")
    ctx = {"run_id": None, "scope_rules": rules, "_transport": httpx.MockTransport(handler)}
    if extra is not None:
        ctx.update(extra)
    out = _run(toolbelt._http_probe({"url": url}, ctx))
    return out, sent


@pytest.mark.parametrize("loc", [
    "http://10.9.9.9/secret",             # host ngoài scope
    "http://169.254.169.254/latest/",     # cloud metadata
    "http://127.0.0.1/admin",             # loopback
    "http://10.1.0.5@10.9.9.9/",          # userinfo trick
    "ftp://10.1.0.5/x", "file:///etc/passwd", "gopher://10.1.0.5/",  # scheme lạ
    "http://[::1]/", "http://2130706433/", "http://0x7f.1/",         # mã hoá IP
    "//10.9.9.9/x",                        # scheme-relative
])
def test_b2_redirect_out_of_scope_not_followed(loc):
    out, sent = _probe(loc)
    assert sent == ["http://10.1.0.5/start"], sent      # request thứ hai KHÔNG được gửi
    assert out["status_code"] == 302
    assert "redirect_blocked" in out


def test_b2_in_scope_redirect_followed():
    out, sent = _probe("/landing")
    assert sent == ["http://10.1.0.5/start", "http://10.1.0.5/landing"]
    assert out["status_code"] == 200 and out["title"] == "reached"
    assert out["redirect_chain"] == ["http://10.1.0.5/landing"]


def test_b2_port_pinned_in_url_rule():
    rules = [{"type": "url", "value": "http://93.184.216.34:8080", "mode": "allow"}]
    out, sent = _probe("http://93.184.216.34:9999/x", rules=rules, url="http://93.184.216.34:8080/start")
    assert len(sent) == 1 and "redirect_blocked" in out


def test_b2_idn_redirect_to_other_host_blocked(monkeypatch):
    rules = [{"type": "domain", "value": "example.com", "include_subdomains": True, "mode": "allow"}]
    monkeypatch.setattr(scope, "_dangerous_ip", lambda ip: False)
    monkeypatch.setattr(scope.socket, "getaddrinfo", lambda h, p: [(2, 1, 6, "", ("93.184.216.34", 0))])
    out, sent = _probe("http://exämple.com.evil.test/", rules=rules, url="http://example.com/start")
    assert len(sent) == 1 and "redirect_blocked" in out


def test_b2_redirect_loop_capped():
    sent = []

    def handler(req):
        sent.append(1)
        return httpx.Response(302, headers={"location": "/start"})
    ctx = {"scope_rules": REDIR_RULES, "_transport": httpx.MockTransport(handler)}
    out = _run(toolbelt._http_probe({"url": "http://10.1.0.5/start"}, ctx))
    assert len(sent) == toolbelt._MAX_REDIRECTS + 1 and "redirect_blocked" in out


def test_b2_no_scope_in_ctx_fails_closed():
    sent = []

    def handler(req):
        sent.append(1)
        return httpx.Response(302, headers={"location": "http://10.1.0.5/x"})
    out = _run(toolbelt._http_probe({"url": "http://10.1.0.5/start"},
                                    {"_transport": httpx.MockTransport(handler)}))
    assert len(sent) == 1 and out["status_code"] == 302


# ───── B3: ffuf wordlist đọc file tuỳ ý ─────
@pytest.fixture
def wl_env(tmp_path, monkeypatch):
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("admin\n")
    sibling = tmp_path / "wordlists-evil"
    sibling.mkdir()
    (sibling / "x.txt").write_text("secret\n")
    secret = tmp_path / "secret.txt"
    secret.write_text("root:x:0:0\n")
    (allowed / "link.txt").symlink_to(secret)              # symlink thoát allowlist
    (allowed / "dirlink").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setenv("VULNGUARD_WORDLIST_DIRS", str(allowed))
    monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/usr/bin/" + b)
    seen = {}

    async def fake(argv, timeout):
        seen["argv"] = argv
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    return tmp_path, allowed, seen


def _ffuf(wordlist):
    return _run(toolbelt._content_discovery({"url": "http://10.1.0.5/", "wordlist": wordlist}))


def test_b3_etc_passwd_rejected(wl_env):
    _, _, seen = wl_env
    out = _ffuf("/etc/passwd")
    assert out["ran"] is False and "argv" not in seen


def test_b3_rejects_traversal_symlink_and_odd_paths(wl_env):
    tmp, allowed, seen = wl_env
    for bad in [str(allowed / ".." / "secret.txt"), str(allowed / "link.txt"),
                str(allowed / "dirlink" / "secret.txt"), str(tmp / "wordlists-evil" / "x.txt"),
                str(tmp / "secret.txt"), "relative.txt", str(allowed / "ok.txt") + ":KEYWORD",
                str(allowed), str(allowed / "missing.txt"), "/proc/self/environ", "/etc/shadow\x00.txt"]:
        out = _ffuf(bad)
        assert out["ran"] is False, bad
    assert "argv" not in seen


def test_b3_allowlisted_wordlist_still_works(wl_env):
    _, allowed, seen = wl_env
    out = _ffuf(str(allowed / "ok.txt"))
    assert out == {"ran": True}
    w = seen["argv"][seen["argv"].index("-w") + 1]
    assert w == str((allowed / "ok.txt").resolve())


def test_b3_default_wordlist_is_allowlisted():
    assert toolbelt.DEFAULT_WORDLIST.startswith("/usr/share/seclists/")
    assert any(toolbelt.DEFAULT_WORDLIST.startswith(d) for d in ["/usr/share/seclists"])


# ───── B4: nuclei tag dos/intrusive/fuzz chạy không cần duyệt ─────
NUCLEI_RULES = [{"type": "ip", "value": "10.1.0.5", "mode": "allow"}]


def _nuclei_tool():
    t = toolbelt.get_tool("web_vuln_scan")
    return t


@pytest.fixture
def nuclei_calls(monkeypatch):
    calls = []

    async def fake_run_nuclei(**kw):
        calls.append(kw)
        return [], {"error": None}
    import scanner.crawler.nuclei_runner as nr
    monkeypatch.setattr(nr, "run_nuclei", fake_run_nuclei)
    return calls


@pytest.mark.parametrize("tags", [
    ["dos"], ["fuzz"], ["intrusive"], ["dos", "fuzz", "intrusive"], ["cve", "DoS"], ["cve,dos"],
    [" Intrusive "], ["bruteforce"], ["dast"], "dos", ["cve", 5], {"dos": 1},
])
def test_b4_dangerous_tags_need_approval_in_every_mode(tags, monkeypatch):
    t = _nuclei_tool()
    monkeypatch.setattr(t, "available", lambda: True)
    for mode in (AutonomyMode.AUTONOMOUS_IN_SCOPE, AutonomyMode.GUIDED):
        d, _ = decide_action(t, {"targets": ["http://10.1.0.5/"], "tags": tags}, mode, NUCLEI_RULES)
        assert d == "needs_approval", (tags, mode)


def test_b4_safe_tags_still_autorun(monkeypatch):
    t = _nuclei_tool()
    monkeypatch.setattr(t, "available", lambda: True)
    for tags in (None, [], ["cve", "exposure", "misconfig"]):
        inp = {"targets": ["http://10.1.0.5/"]}
        if tags is not None:
            inp["tags"] = tags
        d, _ = decide_action(t, inp, AutonomyMode.AUTONOMOUS_IN_SCOPE, NUCLEI_RULES)
        assert d == "execute"


def test_b4_runner_refuses_dangerous_tags_without_approval(nuclei_calls):
    out = _run(toolbelt._web_vuln_scan({"targets": ["http://10.1.0.5/"], "tags": ["dos", "fuzz", "intrusive"]},
                                       {"run_id": None}))
    assert out["ran"] is False and nuclei_calls == []
    out = _run(toolbelt._web_vuln_scan({"targets": ["http://10.1.0.5/"], "tags": ["cve", 1]}, {"approved": True}))
    assert out["ran"] is False and nuclei_calls == []   # kiểu lạ: fail closed kể cả khi đã duyệt


def test_b4_runner_always_excludes_dangerous_tags_by_default(nuclei_calls):
    _run(toolbelt._web_vuln_scan({"targets": ["http://10.1.0.5/"], "tags": ["cve"]}, {"run_id": None}))
    kw = nuclei_calls[-1]
    assert {"dos", "intrusive", "fuzz", "bruteforce"} <= set(kw["exclude_tags"])
    assert kw["tags"] == ["cve"] and kw["fuzz"] is False


def test_b4_approved_run_only_unblocks_requested_tags(nuclei_calls):
    _run(toolbelt._web_vuln_scan({"targets": ["http://10.1.0.5/"], "tags": ["dos"]}, {"approved": True}))
    kw = nuclei_calls[-1]
    assert "dos" not in kw["exclude_tags"] and "intrusive" in kw["exclude_tags"]


def test_b4_nuclei_argv_contains_etags():
    from scanner.crawler.nuclei_runner import build_command
    argv = build_command("t.txt", ["high"], ["cve"], False, 50, exclude_tags=sorted(toolbelt.DANGEROUS_NUCLEI_TAGS))
    etags = argv[argv.index("-etags") + 1].split(",")
    assert {"dos", "intrusive", "fuzz"} <= set(etags)


# ───── Verifier findings (PR #26 review) ─────
FUZZ_RULES = [{"type": "domain", "value": "inscope.lab", "include_subdomains": True, "mode": "allow"}]


@pytest.mark.parametrize("url", [
    "http://FUZZ.inscope.lab/", "https://FUZZ.inscope.lab", "http://api.FUZZ.inscope.lab/x",
    "http://FUZZ/", "http://inscope.lab:FUZZ/", "FUZZ.inscope.lab", "FUZZ://inscope.lab/",
])
def test_v1_ffuf_fuzz_in_authority_rejected(wl_env, url):
    _, _, seen = wl_env
    out = _run(toolbelt._content_discovery({"url": url}))
    assert out["ran"] is False and "argv" not in seen


def test_v1_ffuf_fuzz_in_path_and_default_still_ok(wl_env, monkeypatch):
    _, allowed, seen = wl_env
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: str(allowed / "ok.txt"))
    _run(toolbelt._content_discovery({"url": "http://Inscope.LAB/api/FUZZ"}))
    assert seen["argv"][seen["argv"].index("-u") + 1] == "http://inscope.lab/api/FUZZ"
    _run(toolbelt._content_discovery({"url": "http://inscope.lab:8080/"}))
    assert seen["argv"][seen["argv"].index("-u") + 1] == "http://inscope.lab:8080/FUZZ"


IDN_RULES = [{"type": "domain", "value": "fass.lab", "include_subdomains": False, "mode": "allow"},
             {"type": "ip", "value": "10.1.0.5", "mode": "allow"}]


@pytest.mark.parametrize("host", ["faß.lab", "http://faß.lab/x", "https://faß.lab:8443/", "fasß.lab"])
def test_v2_idna_2003_vs_2008_mismatch_rejected(host):
    with pytest.raises(ScopeError):
        canonicalize_target(host)
    assert check_target(host, IDN_RULES)[0] is False
    assert check_target("fass.lab", IDN_RULES)[0] is True       # tên ASCII thật vẫn in-scope


def test_v2_http_probe_does_not_send_idna_mismatch():
    sent = []

    def handler(req):
        sent.append(str(req.url))
        return httpx.Response(200, text="x")
    out = _run(toolbelt._http_probe({"url": "http://faß.lab/toplevel"},
                                    {"scope_rules": IDN_RULES, "_transport": httpx.MockTransport(handler)}))
    assert sent == [] and out["ran"] is False


def test_v2_idna_redirect_hop_blocked():
    out, sent = _probe("http://faß.lab/idna", rules=IDN_RULES)
    assert sent == ["http://10.1.0.5/start"] and "redirect_blocked" in out


def test_v2_canonical_url_is_ascii_and_stable():
    from scanner.pentest.scope import canonical_url
    assert canonical_url("HTTP://bücher.example.com:8080/a?b=1") == "http://xn--bcher-kva.example.com:8080/a?b=1"
    assert canonical_url("Example.COM.") == "example.com"
    assert canonical_url("http://[2001:db8::1]:81/x") == "http://[2001:db8::1]:81/x"


def test_v2_tools_receive_canonical_targets(nuclei_calls):
    _run(toolbelt._web_vuln_scan({"targets": ["HTTP://Example.COM./a"]}, {}))
    assert nuclei_calls[-1]["targets"] == ["http://example.com/a"]


def test_v3_nuclei_agent_runs_disable_redirects_and_interactsh(nuclei_calls):
    from scanner.crawler.nuclei_runner import build_command
    _run(toolbelt._web_vuln_scan({"targets": ["http://10.1.0.5/"]}, {}))
    assert nuclei_calls[-1]["safe_net"] is True
    argv = build_command("t.txt", ["high"], [], False, 50, safe_net=True)
    assert "-dr" in argv and "-ni" in argv
    assert "-dr" not in build_command("t.txt", ["high"], [], False, 50)   # webscans không đổi


@pytest.mark.parametrize("inp", [
    {"targets": "http://10.1.0.5/", "url": "http://evil.example"},   # C5: fallback `url`
    {"url": "http://evil.example"}, {"targets": []}, {"targets": [1]}, {"targets": ["a b"]},
])
def test_v4_nuclei_targets_must_be_list_of_checked_strings(nuclei_calls, inp):
    out = _run(toolbelt._web_vuln_scan(inp, {}))
    assert out["ran"] is False and nuclei_calls == []


def test_v7_cidr_refused_when_non_ip_deny_rule_present():
    rules = NET24 + [{"type": "domain", "value": "db.corp", "mode": "deny"}]
    assert check_target("10.1.0.0/25", rules)[0] is False
    assert check_target("10.1.0.5", rules)[0] is True       # IP đơn không đổi


def test_v8_single_host_cidr_consistent(monkeypatch):
    async def fake(argv, timeout):
        return {"ran": True, "argv": argv}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    out = _run(toolbelt._port_scan({"host": "172.18.0.2/32"}))
    assert out["ran"] is True and out["argv"][-1] == "172.18.0.2"
