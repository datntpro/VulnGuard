"""P2-3: các mô-đun của gateway (docker/pentest-egress/vg_egw) — DNS allow-list, kho policy, addon mitmproxy (mitmproxy giả), nflog, reload.

Không cần Docker/mitmproxy thật; phần Docker thật ở tests/test_egress_lab.py (VG_LAB=1)."""
import base64
import json
import os
import socket
import struct
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("dnslib")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "docker" / "pentest-egress"))

from dnslib import A, DNSRecord, QTYPE, RCODE  # noqa: E402

from scanner.pentest import egress_policy as ep  # noqa: E402
from vg_egw import nflog  # noqa: E402
from vg_egw.dns_allow import MAX_IPS_PER_NAME, DnsAllow  # noqa: E402
from vg_egw.events import ClientMap, Events  # noqa: E402
from vg_egw.nftctl import NftCtl  # noqa: E402
from vg_egw.policy import PolicyStore, StalePolicy  # noqa: E402

PUB1, PUB2 = "93.184.216.34", "93.184.216.35"


def R(t, v, mode="allow", sub=None):
    r = {"type": t, "value": v, "mode": mode}
    if sub is not None:
        r["include_subdomains"] = sub
    return r


class FakeUpstream:
    def __init__(self, records):
        self.records, self.calls = records, []

    def resolve_a(self, name):
        self.calls.append(name)
        v = self.records.get(name)
        if isinstance(v, Exception):
            raise v
        return [(ip, 5) for ip in (v or [])]


class FakeNft:
    def __init__(self):
        self.any, self.ports, self.fail = [], [], False

    def add_any(self, ip, t):
        if self.fail:
            raise RuntimeError("nft down")
        self.any.append((ip, t))

    def add_port(self, ip, port, t):
        self.ports.append((ip, port, t))


def mk(tmp_path, rules, records, version=1, expiry=None, pins=None):
    store = PolicyStore(str(tmp_path / "policy.json"))
    store.write(ep.compile_policy(rules, pins, version, expiry, engagement_id="e1").to_dict())
    nft, ev, now = FakeNft(), Events("e1"), [1000.0]
    up = FakeUpstream(records)
    return DnsAllow(store, up, nft, ev, clock=lambda: now[0]), store, nft, ev, up, now


def q(dns, name, qtype="A"):
    raw = dns.handle(DNSRecord.question(name, qtype).pack(), "10.0.0.2")
    return DNSRecord.parse(raw)


def answers(r):
    return [str(rr.rdata) for rr in r.rr]


# ───────────── DNS allow-list ─────────────
def test_in_scope_name_answered_and_nft_opened(tmp_path):
    dns, _, nft, ev, up, _ = mk(tmp_path, [R("domain", "example.com", sub=True)], {"www.example.com": [PUB1]})
    r = q(dns, "WWW.example.com")
    assert r.header.rcode == RCODE.NOERROR and answers(r) == [PUB1]
    assert nft.any == [(PUB1, 60)] and not nft.ports
    assert [e["kind"] for e in ev.recent] == ["dns_pin_added"]


def test_out_of_scope_name_nxdomain_without_upstream_query(tmp_path):
    dns, _, nft, ev, up, _ = mk(tmp_path, [R("domain", "example.com")], {"oos.lab": [PUB1]})
    r = q(dns, "oos.lab")
    assert r.header.rcode == RCODE.NXDOMAIN and not answers(r)
    assert up.calls == [] and nft.any == []                                   # KHÔNG hỏi upstream (không rò tên ra ngoài)
    assert ev.recent[-1]["kind"] == "dns_denied" and ev.recent[-1]["name"] == "oos.lab"


@pytest.mark.parametrize("qt", ["AAAA", "TXT", "MX", "ANY", "CNAME"])
def test_non_a_queries_for_in_scope_name_are_nodata_not_forwarded(tmp_path, qt):
    dns, _, _, _, up, _ = mk(tmp_path, [R("domain", "example.com")], {"example.com": [PUB1]})
    r = q(dns, "example.com", qt)
    assert r.header.rcode == RCODE.NOERROR and not answers(r) and up.calls == []


def test_dangerous_answers_filtered_rebinding(tmp_path):
    dns, _, nft, ev, _, _ = mk(tmp_path, [R("domain", "rebind.test")],
                               {"rebind.test": ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1", PUB1]})
    r = q(dns, "rebind.test")
    assert answers(r) == [PUB1] and nft.any == [(PUB1, 60)]
    assert {e["ip"] for e in ev.recent if e["kind"] == "dns_filtered"} == {"127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"}


def test_all_answers_dangerous_is_nxdomain(tmp_path):
    dns, _, nft, _, _, _ = mk(tmp_path, [R("domain", "meta.test")], {"meta.test": ["169.254.169.254"]})
    assert q(dns, "meta.test").header.rcode == RCODE.NXDOMAIN and not nft.any


def test_explicit_private_ip_allowed_through_dns(tmp_path):
    dns, _, nft, _, _, _ = mk(tmp_path, [R("domain", "lab.test"), R("ip", "10.1.1.1")], {"lab.test": ["10.1.1.1", "10.1.1.2"]})
    assert answers(q(dns, "lab.test")) == ["10.1.1.1"]


def test_pins_are_added_never_silently_replaced_and_logged(tmp_path):
    dns, _, nft, ev, up, now = mk(tmp_path, [R("domain", "example.com")], {"example.com": [PUB1]})
    q(dns, "example.com")
    up.records["example.com"] = [PUB2]                                        # đổi đáp án giữa chừng
    assert answers(q(dns, "example.com")) == [PUB2]
    assert dns.pins["example.com"].keys() == {PUB1, PUB2}                      # IP cũ KHÔNG bị xoá thầm lặng
    assert [e["kind"] for e in ev.recent if e["kind"].startswith("dns_pin")] == ["dns_pin_added", "dns_pin_changed"]


def test_pin_expiry_and_cap(tmp_path):
    ips = [f"93.184.{i}.1" for i in range(MAX_IPS_PER_NAME + 4)]
    dns, _, nft, ev, up, now = mk(tmp_path, [R("domain", "example.com")], {"example.com": ips})
    assert len(answers(q(dns, "example.com"))) == MAX_IPS_PER_NAME
    assert any(e["kind"] == "dns_pin_overflow" for e in ev.recent)
    now[0] += 4000
    up.records["example.com"] = [PUB1]
    q(dns, "example.com")
    assert dns.pins["example.com"].keys() == {PUB1}


def test_port_pinned_url_opens_only_those_ports(tmp_path):
    dns, _, nft, _, _, _ = mk(tmp_path, [R("url", "https://app.example.com:8443")], {"app.example.com": [PUB1]})
    q(dns, "app.example.com")
    assert nft.ports == [(PUB1, 8443, 60)] and nft.any == []


def test_nft_failure_fails_closed_but_answers(tmp_path):
    dns, _, nft, ev, _, _ = mk(tmp_path, [R("domain", "example.com")], {"example.com": [PUB1]})
    nft.fail = True
    assert answers(q(dns, "example.com")) == [PUB1]                            # câu trả lời vẫn có; nft không mở → kết nối bị drop
    assert any(e["kind"] == "nft_error" for e in ev.recent)


def test_upstream_error_is_servfail(tmp_path):
    dns, *_ = mk(tmp_path, [R("domain", "example.com")], {"example.com": OSError("boom")})
    assert q(dns, "example.com").header.rcode == RCODE.SERVFAIL


def test_malformed_and_multi_question_packets(tmp_path):
    dns, *_ = mk(tmp_path, [R("domain", "example.com")], {})
    assert dns.handle(b"\x00\x01garbage") is None
    two = DNSRecord.question("a.example.com")
    two.add_question(DNSRecord.question("b.example.com").q)
    assert DNSRecord.parse(dns.handle(two.pack())).header.rcode == RCODE.REFUSED


def test_odd_names_denied_without_upstream_query(tmp_path):
    # Tên Unicode không bao giờ tới DNS (trên dây luôn là ASCII/punycode); mơ hồ IDNA2003/2008 do scope.canonicalize_target xử lý
    # và đã phủ ở parity test + addon/URL.
    dns, _, _, _, up, _ = mk(tmp_path, [R("domain", "example.com", sub=True)], {})
    for n in ("example.com.attacker.net", "0x7f.1", "evilexample.com", "xn--zz.attacker.net"):
        assert q(dns, n).header.rcode == RCODE.NXDOMAIN, n
    assert up.calls == []


def test_hot_reload_revalidates_pins_and_snapshot(tmp_path):
    dns, store, nft, ev, up, now = mk(tmp_path, [R("domain", "example.com"), R("domain", "other.test")],
                                      {"example.com": [PUB1], "other.test": [PUB2]})
    q(dns, "example.com")
    q(dns, "other.test")
    any_, ports = dns.snapshot()
    assert {ip for ip, _ in any_} == {PUB1, PUB2}
    store.write(ep.compile_policy([R("domain", "example.com")], None, 2, None, engagement_id="e1").to_dict())   # other.test bị gỡ khỏi scope
    any_, _ = dns.snapshot()
    assert {ip for ip, _ in any_} == {PUB1} and "other.test" not in dns.pins
    assert q(dns, "other.test").header.rcode == RCODE.NXDOMAIN


def test_expired_policy_denies_dns(tmp_path):
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    dns, *_ = mk(tmp_path, [R("domain", "example.com")], {"example.com": [PUB1]}, expiry=past)
    assert q(dns, "example.com").header.rcode == RCODE.NXDOMAIN


# ───────────── PolicyStore / reload ─────────────
def test_policy_store_versioning_and_corruption(tmp_path):
    s = PolicyStore(str(tmp_path / "p.json"))
    assert s.get().version == 0 and not ep.dns_decision(s.get(), "example.com")[0]          # chưa có file → deny-all
    s.write(ep.compile_policy([R("domain", "example.com")], None, 5, None, engagement_id="e").to_dict())
    with pytest.raises(StalePolicy):
        s.write(ep.compile_policy([], None, 5, None).to_dict())
    with pytest.raises(StalePolicy):
        s.write(ep.compile_policy([], None, 4, None).to_dict())
    with pytest.raises(ValueError):
        s.write({"version": 9, "allow": [{"cidr": "bogus"}]})
    Path(s.path).write_text("{not json")
    os.utime(s.path, (1, 1))
    assert s.get().version == 5 and s.last_error                                           # file hỏng → GIỮ policy cũ


def test_policy_store_file_mode_readable_by_unprivileged(tmp_path):
    s = PolicyStore(str(tmp_path / "p.json"))
    s.write(ep.compile_policy([], None, 1, None).to_dict())
    assert Path(s.path).stat().st_mode & 0o044 == 0o044


def test_reload_cli(tmp_path, monkeypatch):
    from vg_egw import main as m
    monkeypatch.setattr(m, "RUN_DIR", str(tmp_path))
    monkeypatch.setattr(m, "APPLIED", str(tmp_path / "applied.version"))
    monkeypatch.setattr("vg_egw.policy.RUN_DIR", str(tmp_path))
    monkeypatch.setattr(m, "PolicyStore", lambda: PolicyStore(str(tmp_path / "policy.json")))
    (tmp_path / "applied.version").write_text("3")
    b64 = lambda d: base64.b64encode(json.dumps(d).encode()).decode()  # noqa: E731
    assert m.reload_cmd(b64(ep.compile_policy([], None, 3, None).to_dict())) == 0
    assert m.reload_cmd(b64(ep.compile_policy([], None, 3, None).to_dict())) == 3             # stale
    assert m.reload_cmd(b64({"version": "x"})) == 2
    assert m.reload_cmd("!!!not-base64") == 2
    assert m.reload_cmd("A" * 700_000) == 2


# ───────────── nft control ─────────────
def test_nftctl_apply_and_add_elements():
    calls = []
    n = NftCtl("eth0", "eth1", ["10.0.0.53"], runner=lambda a, s=None: calls.append((a, s)), ingest=("172.28.0.5", 8000))
    n.apply(ep.compile_policy([R("ip", "10.0.0.5")], None, 1, None), dyn_any=[("1.2.3.4", 30)])
    assert calls[0][0] == ["nft", "-f", "-"] and "10.0.0.5/32" in calls[0][1] and "1.2.3.4 timeout 30s" in calls[0][1] and "172.28.0.5 tcp dport 8000" in calls[0][1]
    n.add_any("5.6.7.8", 61)
    n.add_port("5.6.7.8", 443, 61)
    assert calls[1][0][-1] == "{ 5.6.7.8 timeout 61s }" and calls[2][0][-1] == "{ 5.6.7.8 . 443 timeout 61s }"


# ───────────── nflog ─────────────
def _nflog_msg(prefix: bytes, src: str, dst: str, dport: int) -> bytes:
    ip = (bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + socket.inet_aton(src) + socket.inet_aton(dst)
          + struct.pack("!HHII", 40000, dport, 0, 0))
    attrs = nflog._attr(nflog.NFULA_PREFIX, prefix + b"\0") + nflog._attr(nflog.NFULA_PAYLOAD, ip)
    body = struct.pack("=BBH", 2, 0, 0) + attrs
    return struct.pack("=IHHII", 16 + len(body), (nflog.NFNL_SUBSYS_ULOG << 8) | nflog.NFULNL_MSG_PACKET, 0, 1, 0) + body


def test_nflog_parse_packets():
    buf = _nflog_msg(b"vg-deny ", "10.0.0.2", "172.31.250.20", 80) + _nflog_msg(b"vg-deny-out ", "10.0.0.3", "1.2.3.4", 22)
    pk = list(nflog.parse_packets(buf))
    assert pk[0] == {"prefix": "vg-deny", "src": "10.0.0.2", "dst": "172.31.250.20", "proto": 6, "dport": 80}
    assert pk[1]["dst"] == "1.2.3.4" and pk[1]["dport"] == 22
    assert list(nflog.parse_packets(b"\x00" * 7)) == [] and list(nflog.parse_packets(_nflog_msg(b"x", "1.1.1.1", "2.2.2.2", 1)[:30])) == []


def test_nflog_config_messages_wellformed():
    m = nflog._wrap(nflog.config_message(1), (nflog.NFNL_SUBSYS_ULOG << 8) | nflog.NFULNL_MSG_CONFIG, 1)
    ln, mtype = struct.unpack_from("=IH", m)
    assert ln == len(m) and mtype == 0x401
    assert len(nflog._wrap(nflog.mode_message(1), 0x401, 2)) % 4 == 0


# ───────────── Events / ClientMap ─────────────
def test_events_ring_clientmap_and_queue_drop(tmp_path):
    cm = ClientMap(str(tmp_path / "c.json"))
    cm.add("10.0.0.9", "run1")
    ev = Events("e1", clients=cm, recent=3)
    for i in range(5):
        ev.emit("egress_denied", src="10.0.0.9", dst=f"1.1.1.{i}")
    assert len(ev.recent) == 3 and ev.recent[-1]["run_id"] == "run1"


def test_events_post_batches_to_ingest(tmp_path):
    import threading
    got, done = [], threading.Event()

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b""

    def opener(req, timeout=0):
        got.append((req.headers, json.loads(req.data)))
        done.set()
        return Resp()
    ev = Events("e1", url="http://api/ingest", token="tok", opener=opener)
    ev.emit("dns_denied", name="oos.lab")
    assert done.wait(5)
    hdr, body = got[0]
    assert hdr["Authorization"] == "Bearer tok" and hdr["X-vg-eng"] == "e1" and body["events"][0]["name"] == "oos.lab"


# ───────────── addon mitmproxy (mitmproxy giả) ─────────────
class _Hdrs(dict):
    def items(self, multi=False):
        return super().items()


class _Resp:
    def __init__(self, status, body=b"", headers=None):
        self.status_code, self.raw_content, self.headers = status, body, _Hdrs(headers or {})
        self.timestamp_end = 2.0

    @staticmethod
    def make(status, content=b"", headers=None):
        return _Resp(status, content, headers)


def _install_fake_mitmproxy():
    mp = types.ModuleType("mitmproxy")
    http = types.ModuleType("mitmproxy.http")
    http.Response, http.HTTPFlow = _Resp, object
    mp.http = http
    sys.modules["mitmproxy"], sys.modules["mitmproxy.http"] = mp, http     # addon chỉ cần http.Response.make
    return http


class Flow:
    def __init__(self, scheme, host, port, headers=None, path="/", method="GET"):
        h = _Hdrs({"Host": host if port in (80, 443) else f"{host}:{port}"})
        h.update(headers or {})
        self.request = types.SimpleNamespace(scheme=scheme, host=host, port=port, headers=h, method=method, raw_content=b"",
                                             pretty_url=f"{scheme}://{host}:{port}{path}", url=f"{scheme}://{host}:{port}{path}",
                                             timestamp_start=1.0)
        self.client_conn = types.SimpleNamespace(peername=("10.0.0.2", 5555))
        self.metadata, self.response = {}, None


@pytest.fixture()
def addon(tmp_path):
    _install_fake_mitmproxy()
    import importlib
    import vg_egw.addon as mod
    importlib.reload(mod)
    store = PolicyStore(str(tmp_path / "policy.json"))
    store.write(ep.compile_policy([R("domain", "inscope.lab", sub=False), R("url", "https://api.example.com:8443"), R("ip", "10.1.1.1")],
                                  None, 1, None, engagement_id="e1").to_dict())
    ev = Events("e1")
    return mod.VgScope(store, ev), ev


def test_addon_allows_in_scope_and_records(addon):
    a, ev = addon
    f = Flow("http", "inscope.lab", 80)
    f.request.headers["X-VG-Step"] = "s-1"
    a.requestheaders(f)
    assert f.response is None and "X-VG-Step" not in f.request.headers and f.metadata["vg_step"] == "s-1"     # header nội bộ không lộ ra target
    f.response = _Resp(200, b"ok", {"Content-Type": "text/plain"})
    a.response(f)
    http_ev = [e for e in ev.recent if e["kind"] == "http"][0]
    assert http_ev["status"] == 200 and http_ev["host"] == "inscope.lab" and http_ev["step"] == "s-1" and http_ev["resp_body"] == "ok"


@pytest.mark.parametrize("scheme,host,port", [("http", "oos.lab", 80), ("http", "10.1.1.2", 80), ("http", "169.254.169.254", 80),
                                              ("http", "127.0.0.1", 80), ("https", "api.example.com", 443), ("http", "api.example.com", 8443)])
def test_addon_denies_out_of_scope(addon, scheme, host, port):
    a, ev = addon
    f = Flow(scheme, host, port)
    a.requestheaders(f)
    assert f.response is not None and f.response.status_code == 403 and f.response.headers["X-VG-Egress"] == "denied"
    assert ev.recent[-1]["kind"] == "egress_denied" and ev.recent[-1]["via"] == "proxy"


def test_addon_port_pinned_url_rule_allows_exact_port(addon):
    a, _ = addon
    f = Flow("https", "api.example.com", 8443)
    a.requestheaders(f)
    assert f.response is None


def test_addon_blocks_host_header_override(addon):
    a, ev = addon
    f = Flow("http", "inscope.lab", 80, headers={"Host": "oos.lab"})
    a.requestheaders(f)
    assert f.response.status_code == 403 and "Host header" in ev.recent[-1]["reason"]
    g = Flow("http", "inscope.lab", 80, headers={"Host": "inscope.lab:8080"})          # cổng Host ≠ cổng kết nối
    a.requestheaders(g)
    assert g.response.status_code == 403


def test_addon_connect_checks_host_port(addon):
    a, _ = addon
    ok, bad = Flow("https", "api.example.com", 8443, method="CONNECT"), Flow("https", "api.example.com", 22, method="CONNECT")
    a.http_connect(ok)
    a.http_connect(bad)
    assert ok.response is None and bad.response.status_code == 403
    oos = Flow("https", "oos.lab", 443, method="CONNECT")
    a.http_connect(oos)
    assert oos.response.status_code == 403


def test_addon_flags_redirect_out_of_scope_each_hop_rechecked(addon):
    a, ev = addon
    f = Flow("http", "inscope.lab", 80, path="/redir")
    a.requestheaders(f)
    f.response = _Resp(302, b"", {"Location": "http://oos.lab/x"})
    a.response(f)
    assert any(e["kind"] == "egress_redirect_oos" and "oos.lab" in e["location"] for e in ev.recent)
    hop2 = Flow("http", "oos.lab", 80, path="/x")             # client tự theo redirect → hop mới đi qua requestheaders và bị chặn
    a.requestheaders(hop2)
    assert hop2.response.status_code == 403


def test_addon_expired_policy_denies_everything(tmp_path):
    _install_fake_mitmproxy()
    import importlib
    import vg_egw.addon as mod
    importlib.reload(mod)
    store = PolicyStore(str(tmp_path / "policy.json"))
    store.write(ep.compile_policy([R("domain", "inscope.lab")], None, 1, datetime.now(timezone.utc) - timedelta(seconds=1), engagement_id="e").to_dict())
    a = mod.VgScope(store, Events("e"))
    f = Flow("http", "inscope.lab", 80)
    a.requestheaders(f)
    assert f.response.status_code == 403
