"""P0 safety & truthful-results: scope DNS re-check, PII redaction, tool-skip truthfulness."""
import asyncio

from scanner.pentest import scope
from scanner.cloud_ai import redact, redact_pii


# ── 0.6 scope: phân giải DNS, chặn IP nội bộ/metadata (chống SSRF/rebinding) ──
def test_resolved_blocks_internal_ip():
    rules = [{"type": "domain", "value": "evil.test", "mode": "allow"}]
    # domain nằm trong scope nhưng resolve về 127.0.0.1 → chặn
    ok, reason = scope.check_target_resolved("http://evil.test/x", rules,
                                             _resolver=lambda h: ["127.0.0.1"])
    assert ok is False and ("nội bộ" in reason or "metadata" in reason or "rebinding" in reason.lower())


def test_resolved_blocks_metadata():
    rules = [{"type": "domain", "value": "evil.test", "mode": "allow"}]
    ok, _ = scope.check_target_resolved("evil.test", rules, _resolver=lambda h: ["169.254.169.254"])
    assert ok is False


def test_resolved_allows_public_ip_in_scope():
    rules = [{"type": "domain", "value": "ok.test", "mode": "allow"}]
    ok, _ = scope.check_target_resolved("https://ok.test", rules, _resolver=lambda h: ["93.184.216.34"])
    assert ok is True


def test_resolved_allows_internal_when_explicitly_scoped():
    rules = [{"type": "domain", "value": "lab.test", "mode": "allow"},
             {"type": "cidr", "value": "10.0.0.0/8", "mode": "allow"}]
    ok, _ = scope.check_target_resolved("lab.test", rules, _resolver=lambda h: ["10.1.2.3"])
    assert ok is True


# ── 0.7 redaction PII ──
def test_redact_pii():
    t = "CCCD 001099012345 gọi 0912345678 email a@b.vn nội bộ 192.168.1.5"
    r = redact_pii(t)
    assert "001099012345" not in r and "[CCCD]" in r
    assert "0912345678" not in r and "[SĐT]" in r
    assert "a@b.vn" not in r and "[EMAIL]" in r
    assert "192.168.1.5" not in r and "[IP_NỘI_BỘ]" in r


def test_redact_combines_secret_and_pii():
    r = redact("token=\"supersecretvalue123\" email x@y.vn")
    assert "supersecretvalue123" not in r and "x@y.vn" not in r


# ── 0.1 orchestrator: tool thiếu → "skipped", KHÔNG phải 0 lỗi im lặng ──
def test_missing_tool_marked_skipped():
    from scanner.orchestrator import Orchestrator

    class _FakeMissing:
        tool_name = "ghost-tool"
        def __init__(self, p): pass
        def is_available(self): return False
        async def scan(self): return []

    orch = Orchestrator("/tmp", ["SAST"])
    # chạy trực tiếp hàm timed trên scanner giả
    findings, dur, err = asyncio.get_event_loop().run_until_complete(
        orch._run_scanner_timed(_FakeMissing("/tmp")))
    assert findings is None and "PATH" in err


# ── 0.4 ownership verification ──
def test_ownership_dns_txt():
    from scanner import ownership as own
    tok = "vulnguard-abc123"
    assert own.verify_dns_txt("x.test", tok, _resolver=lambda h: [f"vulnguard-verify={tok}"]) is True
    assert own.verify_dns_txt("x.test", tok, _resolver=lambda h: ["other=1"]) is False


def test_ownership_well_known():
    import asyncio as _a
    from scanner import ownership as own
    tok = "vulnguard-xyz"
    async def good(url): return f"  {tok}\n"
    async def bad(url): return "nope"
    assert _a.get_event_loop().run_until_complete(own.verify_well_known("https://x.test", tok, _fetcher=good)) is True
    assert _a.get_event_loop().run_until_complete(own.verify_well_known("https://x.test", tok, _fetcher=bad)) is False
