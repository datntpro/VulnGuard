"""P2-3a: scope→EgressPolicy compiler, quyết định dùng chung (DNS/HTTP/connect) và ruleset nft — thuần, không Docker.

Điểm mấu chốt: gateway KHÔNG có bản cài đặt luật scope thứ hai — mọi quyết định đi qua scope.check_target. Test `parity` đối chiếu
trực tiếp với scope.py trên MỌI target xuất hiện trong kịch bản P1-6 (eval/harness/scenarios.py)."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner.pentest import egress_policy as ep
from scanner.pentest import scope

FIX = Path(__file__).parent / "fixtures" / "egress"
PUB1, PUB2, PUB3 = "93.184.216.34", "93.184.216.35", "198.51.100.0"   # 198.51.100/24 là TEST-NET-2 (reserved) → dùng PUB cho "công khai"


def R(t, v, mode="allow", sub=None):
    r = {"type": t, "value": v, "mode": mode}
    if sub is not None:
        r["include_subdomains"] = sub
    return r


def pol(rules, pins=None, expiry=None, version=1, **kw):
    return ep.compile_policy(rules, pins, version, expiry, engagement_id="e1", **kw)


# ───────────── compiler ─────────────
def test_domain_rule_goes_to_dns_allow_with_subdomains():
    p = pol([R("domain", "example.com", sub=True), R("domain", "exact.test", sub=False)])
    assert p.dns_allow == ("example.com", ".example.com", "exact.test")
    assert p.allow == ()


def test_url_rule_pins_are_port_pinned_and_dns_exact():
    p = pol([R("url", "https://app.example.com:8443")], pins={"app.example.com": [PUB1]})
    assert p.dns_allow == ("app.example.com",)
    assert [(r.cidr, r.ports) for r in p.allow] == [(f"{PUB1}/32", (8443,))]


def test_url_rule_default_ports_and_schemeless():
    p = pol([R("url", "https://a.example.com"), R("url", "b.example.com")],
            pins={"a.example.com": [PUB1], "b.example.com": [PUB2]})
    ports = {r.cidr: r.ports for r in p.allow}
    assert ports[f"{PUB1}/32"] == (443,) and ports[f"{PUB2}/32"] == (80, 443)


def test_domain_pins_open_any_port():
    p = pol([R("domain", "example.com")], pins={"example.com": [PUB1]})
    assert [(r.cidr, r.ports) for r in p.allow] == [(f"{PUB1}/32", None)]


def test_ip_and_cidr_rules_allow_private_only_when_explicit():
    p = pol([R("ip", "10.0.0.5"), R("cidr", "172.31.250.0/24")])
    assert {r.cidr for r in p.allow} == {"10.0.0.5/32", "172.31.250.0/24"}
    # tên (không khai ip) trỏ về IP riêng → KHÔNG vào allow (mirror _ip_explicitly_allowed)
    q = pol([R("domain", "internal.example.com")], pins={"internal.example.com": ["10.1.2.3", PUB1]})
    assert [r.cidr for r in q.allow] == [f"{PUB1}/32"]


def test_url_rule_with_private_ip_literal_needs_explicit_ip_rule():
    assert pol([R("url", "http://10.0.0.7:8080")]).allow == ()
    q = pol([R("url", "http://10.0.0.7:8080"), R("ip", "10.0.0.7")])
    assert ("10.0.0.7/32", None) in {(r.cidr, r.ports) for r in q.allow}      # ip rule tường minh → mọi cổng (như scope.check_target)


def test_deny_rules_and_always_deny():
    p = pol([R("cidr", "10.0.0.0/24"), R("ip", "10.0.0.5", "deny"), R("domain", "bad.example.com", "deny", sub=True)],
            extra_always_deny=["172.30.0.0/16", "not-a-cidr"])
    assert p.deny == ("10.0.0.5/32",)
    assert p.dns_deny == ("bad.example.com", ".bad.example.com")
    assert "169.254.0.0/16" in p.always_deny and "127.0.0.0/8" in p.always_deny and "172.30.0.0/16" in p.always_deny
    assert ep.connect_decision(p, "10.0.0.4", 80)[0] and not ep.connect_decision(p, "10.0.0.5", 80)[0]
    assert not ep.connect_decision(p, "169.254.169.254", 80)[0]


def test_always_deny_beats_explicit_allow():
    p = pol([R("cidr", "169.254.0.0/16"), R("ip", "127.0.0.1")])
    assert not ep.connect_decision(p, "169.254.169.254", 80)[0] and not ep.connect_decision(p, "127.0.0.1", 80)[0]
    assert "169.254.0.0/16" in ep.render_nft(p)


def test_pin_for_denied_or_out_of_scope_name_is_dropped():
    p = pol([R("domain", "example.com"), R("domain", "bad.example.com", "deny")],
            pins={"bad.example.com": [PUB1], "other.org": [PUB2]})
    assert p.allow == ()


def test_expiry_roundtrip_and_expired():
    exp = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    p = pol([R("ip", "10.0.0.5")], expiry=exp)
    d = p.to_dict()
    assert d["expires_at"] == "2030-01-02T03:04:05Z"
    assert ep.EgressPolicy.from_dict(json.loads(json.dumps(d))) == p
    assert not p.expired(exp - timedelta(seconds=1)) and p.expired(exp)
    assert not ep.connect_decision(p, "10.0.0.5", 80, now=exp)[0]
    assert not ep.dns_decision(pol([R("domain", "a.test")], expiry=exp), "a.test", now=exp)[0]


@pytest.mark.parametrize("bad", [
    {"version": "1"}, {"version": -1}, {"version": True}, {"version": 1, "allow": [{"cidr": "nope"}]},
    {"version": 1, "allow": [{"cidr": "10.0.0.0/8", "ports": [0]}]}, {"version": 1, "allow": [{"cidr": "10.0.0.0/8", "ports": []}]},
    {"version": 1, "allow": [{"cidr": "10.0.0.0/8", "proto": "udp"}]}, {"version": 1, "deny": ["x"]},
    {"version": 1, "expires_at": "tomorrow"}, {"version": 1, "dns_allow": [""]}, "x", None,
])
def test_from_dict_rejects_garbage(bad):
    with pytest.raises(ValueError):
        ep.EgressPolicy.from_dict(bad)


def test_deny_all_policy_denies_everything():
    p = ep.deny_all_policy("e1")
    assert not ep.dns_decision(p, "example.com")[0] and not ep.http_decision(p, "http", "example.com", 80)[0]
    assert not ep.connect_decision(p, PUB1, 80)[0]
    assert "elements" not in re.findall(r"set allowed_any \{[^}]*\}", ep.render_nft(p))[0]


# ───────────── quyết định dùng chung ─────────────
def test_filter_answers_drops_v6_internal_and_garbage():
    p = pol([R("domain", "example.com"), R("ip", "10.9.9.9")])
    kept, dropped = ep.filter_answers(p, [PUB1, "10.9.9.9", "10.1.1.1", "127.0.0.1", "169.254.169.254", "::1", "2001:db8::1", "x", PUB1])
    assert kept == [PUB1, "10.9.9.9"]
    assert {d[0] for d in dropped} == {"10.1.1.1", "127.0.0.1", "169.254.169.254", "::1", "2001:db8::1", "x"}


def test_filter_answers_respects_deny_cidr_even_if_public():
    p = pol([R("domain", "example.com"), R("cidr", "93.184.216.0/24", "deny")])
    assert ep.filter_answers(p, [PUB1])[0] == []


def test_dns_decision_idna_and_odd_names():
    p = pol([R("domain", "example.com", sub=True)])
    assert ep.dns_decision(p, "WWW.Example.COM.")[0]
    for bad in ("example.com.evil.net", "evilexample.com", "faß.example.com", "1.2.3.4", "ex ample.com", "", "a" * 300 + ".example.com",
                "*.example.com", "0x7f.1"):
        assert not ep.dns_decision(p, bad)[0], bad


def test_dns_decision_deny_wins():
    p = pol([R("domain", "example.com", sub=True), R("domain", "admin.example.com", "deny", sub=False)])
    assert ep.dns_decision(p, "www.example.com")[0] and not ep.dns_decision(p, "admin.example.com")[0]


def test_http_decision_url_ports_and_schemes():
    p = pol([R("url", "https://app.example.com:8443"), R("domain", "open.example.com", sub=False)])
    assert ep.http_decision(p, "https", "app.example.com", 8443)[0]
    assert not ep.http_decision(p, "https", "app.example.com", 443)[0]
    assert not ep.http_decision(p, "http", "app.example.com", 8443)[0]        # scheme của rule url là https
    assert ep.http_decision(p, "http", "open.example.com", 8080)[0]            # rule domain: mọi cổng
    assert ep.http_decision(p, None, "app.example.com", 8443)[0]               # CONNECT tunnel: host:port
    assert not ep.http_decision(p, None, "app.example.com", 22)[0]
    assert not ep.http_decision(p, "ftp", "open.example.com", 21)[0]


def test_http_decision_blocks_ip_literals_and_always_deny():
    p = pol([R("domain", "example.com"), R("cidr", "169.254.0.0/16"), R("ip", "10.0.0.5")])
    assert not ep.http_decision(p, "http", "169.254.169.254", 80)[0]
    assert not ep.http_decision(p, "http", "10.0.0.6", 80)[0]
    assert ep.http_decision(p, "http", "10.0.0.5", 80)[0]
    assert not ep.http_decision(p, "http", "::1", 80)[0]


def test_egress_ports_deny_url_port_narrows():
    rules = [R("domain", "example.com", sub=False), R("url", "http://example.com:8080", "deny")]
    assert ep.egress_ports("example.com", rules) == {80, 443}               # chặt hơn scope (mọi cổng) — nft không biểu diễn "trừ X"
    assert ep.egress_ports("example.com", [R("url", "https://example.com:8443"), R("url", "http://example.com:8443", "deny")]) == set()
    assert ep.egress_ports("example.com", [R("domain", "example.com")]) is None
    assert ep.egress_ports("nope.test", rules) == set()


def test_port_pin_denies_through_proxy_and_nft_alike():
    p = pol([R("url", "http://example.com:8080")], pins={"example.com": [PUB1]})
    assert ep.connect_decision(p, PUB1, 8080)[0] and not ep.connect_decision(p, PUB1, 80)[0]
    assert ep.http_decision(p, "http", "example.com", 8080)[0] and not ep.http_decision(p, "http", "example.com", 80)[0]


# ───────────── nft ─────────────
def _golden_policy():
    rules = [R("url", "http://10.20.0.7:8080", "deny"), R("domain", "inscope.lab", sub=False), R("ip", "172.31.250.10"), R("cidr", "10.20.0.0/16"), R("ip", "10.20.0.66", "deny"),
             R("url", "https://app.example.com:8443"), R("url", "http://pinned.example.com:8081")]
    return pol(rules, pins={"app.example.com": [PUB1, PUB2], "pinned.example.com": [PUB3.replace("198.51.100.0", "93.184.216.40")]},
               expiry=datetime(2030, 1, 1, tzinfo=timezone.utc), version=7, extra_always_deny=["172.17.0.0/16", "172.28.0.0/16"])


def test_render_nft_golden():
    text = ep.render_nft(_golden_policy(), eng_if="eth0", out_if="eth1", upstream_dns=["10.0.0.53"], ingest=("172.28.0.5", 8000),
                         dyn_any=[("1.2.3.4", 60)], dyn_ports=[("1.2.3.5", 443, 90)])
    g = FIX / "basic.nft"
    if not g.exists():     # bootstrap lần đầu; sau đó là golden file được review
        g.write_text(text)
    assert text == g.read_text()


def test_render_nft_invariants():
    t = ep.render_nft(_golden_policy())
    for hook in ("input", "forward", "output"):
        assert re.search(rf"chain {hook} \{{\s+type filter hook {hook} priority 0; policy drop;", t)
    assert t.count("meta nfproto ipv6 drop") == 3                             # IPv6 drop ở cả ba hook
    assert "udp" not in t.replace("udp dport 5353", "").replace("udp dport 53 ", "")   # UDP chỉ tới DNS của gateway / redirect
    assert "icmp" not in t
    fwd = t.split("chain forward")[1].split("chain output")[0]
    assert fwd.index("@denied") < fwd.index("@allowed_any")                    # deny TRƯỚC allow
    assert fwd.rstrip().endswith("}") and 'iifname "eth0" log group 1 prefix "vg-deny " drop' in fwd   # default-deny có log


def test_render_nft_denied_set_contains_always_and_deny_collapsed():
    t = ep.render_nft(_golden_policy())
    denied = re.search(r"set denied \{[^}]*elements = \{ ([^}]*) \}", t).group(1)
    for c in ("127.0.0.0/8", "169.254.0.0/16", "172.17.0.0/16", "172.28.0.0/16", "10.20.0.66/32"):
        assert c in denied
    assert "::1" not in t and "fe80" not in t                                  # v6 không vào ruleset v4


def test_render_nft_ports_only_slash32_and_v6_rules_skipped():
    p = ep.EgressPolicy("e", 1, (ep.EgressRule("2001:db8::/32", None), ep.EgressRule("10.0.0.0/24", None)))
    t = ep.render_nft(p)
    assert "2001:db8" not in t and "10.0.0.0/24" in t
    with pytest.raises(ValueError):
        ep.render_nft(ep.EgressPolicy("e", 1, (ep.EgressRule("10.0.0.0/24", (80,)),)))


def test_render_nft_rejects_injection_in_inputs():
    with pytest.raises(ValueError):
        ep.render_nft(ep.deny_all_policy("e"), eng_if='eth0"; flush ruleset; "')
    with pytest.raises(ValueError):
        ep.render_nft(ep.deny_all_policy("e"), upstream_dns=["1.1.1.1; flush ruleset"])


# ───────────── parity với kịch bản P1-6 ─────────────
def _harvest():
    from eval.harness import scenarios as sc
    out = []
    pat = re.compile(r"https?://[^\s\"'&]+|(?<![\w.-])[a-z0-9-]+\.lab(?::\d+)?|172\.31\.2\d\d\.\d+(?:/\d+)?|169\.254\.169\.254")

    def walk(x):
        if isinstance(x, str):
            out.extend(pat.findall(x))
        elif isinstance(x, dict):
            [walk(v) for v in x.values()]
        elif isinstance(x, (list, tuple)):
            [walk(v) for v in x]
    for s in sc.S:
        walk(s.turns)
        walk(s.targets)
        walk(s.scope_rules)
        for u in list(out):                       # URL nhúng trong tham số redirect (?to=http://oos.lab/x)
            if "to=" in u:
                out.append(u.split("to=", 1)[1].replace("%3F", "?"))
    extra = ["http://oos.lab/", "http://metadata.lab/latest", "http://rebind.lab/", "http://172.31.250.1/", "http://172.31.250.20:8080/",
             "http://[::1]/", "http://2130706433/", "http://0x7f.1/", "http://inscope.lab:8081/", "http://inscope.lab\\@oos.lab/",
             "http://xn--fa-hia.lab/", "http://inscope.lab./", "http://INSCOPE.LAB/", "http://user@inscope.lab/"]
    return sorted(set(out + extra))


def _scenario_rule_sets():
    from eval.harness import scenarios as sc
    seen, sets = set(), []
    for s in sc.S:
        k = json.dumps(s.scope_rules, sort_keys=True)
        if k not in seen:
            seen.add(k)
            sets.append(s.scope_rules)
    return sets


@pytest.mark.parametrize("rules", _scenario_rule_sets(), ids=lambda r: ",".join(f"{x['type']}:{x['value']}" for x in r)[:60])
def test_parity_http_decision_equals_check_target(rules):
    pins = {"inscope.lab": ["172.31.250.10"], "rebind.lab": ["172.31.250.10"]}
    p = pol(rules, pins=pins)
    cands = _harvest()
    assert len(cands) > 15
    for t in cands:
        expect = scope.check_target(t, rules)[0]
        try:
            c = scope.canonicalize_target(t)
        except scope.ScopeError:
            assert expect is False
            got = False
        else:
            if c["kind"] != "url":
                continue
            got = ep.http_decision(p, c["scheme"], c["host"], c["port"])[0]
        assert got == expect, f"{t}: egress={got} scope={expect} rules={rules}"


@pytest.mark.parametrize("rules", _scenario_rule_sets(), ids=lambda r: ",".join(f"{x['type']}:{x['value']}" for x in r)[:60])
def test_parity_dns_decision_equals_check_target_for_names(rules):
    p = pol(rules)
    for t in _harvest():
        try:
            c = scope.canonicalize_target(t)
        except scope.ScopeError:
            continue
        if c["kind"] != "url" or scope._as_ip(c["host"]) is not None:
            continue
        # DNS không biết cổng: tên được trả lời khi scope cho phép tên đó ở BẤT KỲ cổng nào (host trần)
        assert ep.dns_decision(p, c["host"])[0] == scope.check_target(c["host"], rules)[0], (t, rules)


def test_parity_lab_scenario_network_expectations():
    """Các IP/cổng mà kịch bản P1-6 cấm chạm: tripwire, oos, metadata, gateway bridge — mọi tầng của policy đều phải chặn."""
    from eval.harness import scenarios as sc
    p = pol(sc.SCOPE_ONE_HOST, pins={sc.INSCOPE: [sc.INSCOPE_IP]}, extra_always_deny=[sc.LAB_GATEWAY + "/32"])
    assert ep.connect_decision(p, sc.INSCOPE_IP, 80)[0] and ep.connect_decision(p, sc.INSCOPE_IP, 22)[0]   # rule ip: mọi cổng (như scope)
    for ip in ("172.31.250.20", "172.31.250.254", "172.31.251.20", sc.LAB_GATEWAY, "169.254.169.254", "127.0.0.1"):
        assert not ep.connect_decision(p, ip, 80)[0], ip
    assert not ep.dns_decision(p, "oos.lab")[0] and not ep.dns_decision(p, "metadata.lab")[0]
    kept, dropped = ep.filter_answers(p, ["172.31.250.20", sc.INSCOPE_IP])      # rebind.lab: A thứ hai (.20) bị lọc
    assert kept == [sc.INSCOPE_IP] and dropped
    # port-pinned url rule (kịch bản port_pinned_url_port_scan)
    q = pol([R("url", f"http://{sc.INSCOPE}:8081")], pins={sc.INSCOPE: ["93.184.216.40"]})
    assert ep.connect_decision(q, "93.184.216.40", 8081)[0] and not ep.connect_decision(q, "93.184.216.40", 80)[0]


# ───────────── M1: deny url / ip:port / dải / IPv6 → nft ─────────────
def test_deny_url_on_ip_literal_is_compiled_into_denied_ports():
    p = pol([R("cidr", "100.70.0.0/24"), R("url", "http://100.70.0.5:8080", "deny"), R("url", "https://100.70.0.6", "deny")])
    assert {(r.cidr, r.ports) for r in p.deny_ports} == {("100.70.0.5/32", (8080,)), ("100.70.0.6/32", (443,))}
    assert not ep.connect_decision(p, "100.70.0.5", 8080)[0] and ep.connect_decision(p, "100.70.0.5", 80)[0]
    assert not ep.connect_decision(p, "100.70.0.6", 443)[0] and ep.connect_decision(p, "100.70.0.7", 8080)[0]
    t = ep.render_nft(p)
    assert "100.70.0.5 . 8080" in t and "100.70.0.6 . 443" in t
    for chain in (t.split("chain forward")[1].split("chain output")[0], t.split("chain output")[1].split("chain redirect_dns")[0]):
        assert chain.index("@denied_ports") < chain.index("@allowed_any")          # drop TRƯỚC allow, ở forward lẫn output
    assert ep.EgressPolicy.from_dict(json.loads(json.dumps(p.to_dict()))) == p


def test_deny_url_on_ip_with_ip_allow_rule_the_exact_repro():
    p = pol([R("ip", "100.70.0.9"), R("url", "https://100.70.0.9", "deny")])
    assert scope.check_target("100.70.0.9:443", p.rules())[0] is False
    assert ep.connect_decision(p, "100.70.0.9", 443)[0] is False and ep.connect_decision(p, "100.70.0.9", 22)[0] is True


@pytest.mark.parametrize("rules", [
    [R("cidr", "100.70.0.0/24"), R("url", "http://100.70.0.5:8080", "deny")],
    [R("ip", "100.70.0.9"), R("url", "https://100.70.0.9", "deny"), R("url", "100.70.0.9", "deny")],
    [R("cidr", "100.70.0.0/16"), R("cidr", "100.70.1.0/24", "deny"), R("ip", "100.70.2.2", "deny")],              # dải deny
    [R("cidr", "100.70.0.0/24"), R("cidr", "2001:db8::/32", "deny"), R("url", "http://[2001:db8::1]:80", "deny")],  # IPv6 deny
    [R("cidr", "10.0.0.0/8"), R("url", "http://10.1.2.3:80", "deny"), R("cidr", "10.9.0.0/16", "deny")],
])
def test_parity_connect_decision_equals_check_target_for_ip_ports(rules):
    p = pol(rules)
    assert ep.render_nft(p)                                                           # v6 / deny không làm hỏng ruleset
    for ip in ("100.70.0.5", "100.70.0.6", "100.70.0.9", "100.70.1.7", "100.70.2.2", "100.70.3.3", "10.1.2.3", "10.9.1.1", "10.2.2.2", "8.8.8.8"):
        for port in (22, 80, 443, 8080, 8443):
            exp = scope.check_target(f"{ip}:{port}", rules)[0]
            assert ep.connect_decision(p, ip, port)[0] == exp, (ip, port, rules)
    assert not ep.connect_decision(p, "2001:db8::1", 80)[0]                           # IPv6 luôn bị chặn (chặt hơn/bằng scope)


def test_deny_url_on_name_denies_the_whole_name_at_dns():
    """L5: rule deny url `host:port` khớp tên trần → check_target(host) cũng deny → NXDOMAIN cho cả tên (chặt hơn scope), không 'thu hẹp 80/443'."""
    p = pol([R("domain", "example.com", sub=False), R("url", "http://example.com:8080", "deny")], pins={"example.com": [PUB1]})
    assert not ep.dns_decision(p, "example.com")[0] and p.allow == ()
