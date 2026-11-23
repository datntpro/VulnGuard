from scanner.pentest.scope import check_target

RULES = [
    {"type": "domain", "value": "example.com", "include_subdomains": True, "mode": "allow"},
    {"type": "cidr", "value": "10.0.0.0/24", "mode": "allow"},
    {"type": "domain", "value": "admin.example.com", "mode": "deny"},
]


def test_in_scope_domain_and_subdomain():
    assert check_target("https://example.com/x", RULES)[0]
    assert check_target("api.example.com", RULES)[0]


def test_deny_wins():
    assert check_target("admin.example.com", RULES)[0] is False


def test_out_of_scope_blocked():
    assert check_target("evil.com", RULES)[0] is False


def test_cidr_boundaries():
    assert check_target("10.0.0.5", RULES)[0]
    assert check_target("10.0.1.5", RULES)[0] is False


def test_loopback_blocked_unless_explicitly_scoped():
    # P0.6: IP nội bộ/loopback bị chặn cứng TRỪ KHI scope ghi rõ bằng ip/cidr
    # Khớp allow qua DOMAIN nhưng IP là loopback → vẫn chặn
    rules_domain = [{"type": "domain", "value": "localhost", "mode": "allow"}]
    assert check_target("127.0.0.1", rules_domain)[0] is False
    # Không có rule nào → chặn
    assert check_target("127.0.0.1", [])[0] is False
    # Khai báo tường minh bằng CIDR → cho phép (vd pentest app local có chủ đích)
    allow_local = [{"type": "cidr", "value": "127.0.0.0/8", "mode": "allow"}]
    assert check_target("127.0.0.1", allow_local)[0] is True


def test_metadata_ip_blocked():
    # 169.254.169.254 (cloud metadata) chặn trừ khi scope ghi rõ
    assert check_target("169.254.169.254", [{"type": "domain", "value": "x", "mode": "allow"}])[0] is False
