from api.pentest_models import AutonomyMode
from scanner.pentest.gating import decide_action
from scanner.pentest.toolbelt import get_tool

RULES = [{"type": "domain", "value": "example.com", "include_subdomains": True, "mode": "allow"}]


def test_recon_autoruns_in_scope():
    d, _ = decide_action(get_tool("http_probe"), {"url": "https://example.com"},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, RULES)
    assert d == "execute"


def test_out_of_scope_blocked():
    d, _ = decide_action(get_tool("http_probe"), {"url": "https://evil.com"},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, RULES)
    assert d == "block_scope"


def test_intrusive_needs_approval():
    d, _ = decide_action(get_tool("active_http"), {"url": "https://example.com", "method": "POST"},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, RULES)
    assert d == "needs_approval"


def test_guided_mode_gates_active_safe():
    t = get_tool("http_probe")
    d, _ = decide_action(t, {"url": "https://example.com"}, AutonomyMode.GUIDED, RULES)
    assert d == "execute"  # recon vẫn tự chạy


def test_internal_readonly_tool_scope_exempt():
    d, _ = decide_action(get_tool("asset_context"), {"host": "anything"},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, RULES)
    assert d == "execute"
