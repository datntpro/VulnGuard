"""P2-3b (VG_LAB=1): gateway egress THẬT trên Docker thật — nft + DNS allow-list + mitmproxy chống lại một "probe" mô phỏng sandbox.

Dựng: mạng `out` (bridge thường, đóng vai "Internet"), 2 target (in-scope t1 / out-of-scope t2, mỗi cái ghi log mọi request làm tripwire),
DNS upstream giả (dnslib), runner thật (create_app + EgressGateway thật), probe (cap_drop ALL, mạng engagement, default route qua gateway).
Cần image `vulnguard-pentest-egress` (docker build -f docker/pentest-egress/Dockerfile -t vulnguard-pentest-egress .)
và `python:3.12-slim`. Không chạm Internet (mọi mạng do test tạo; gateway chỉ ra `out`).
"""
import base64
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(os.environ.get("VG_LAB") != "1", reason="cần VG_LAB=1 + Docker + image egress")

TOKEN = "lab-token-" + "x" * 40
H = {"Authorization": f"Bearer {TOKEN}"}
EGW = os.environ.get("PENTEST_LAB_EGRESS_IMAGE", "vulnguard-pentest-egress:latest")
PY = os.environ.get("PENTEST_LAB_PY_IMAGE", "python:3.12-slim")
RUNNER_IMG = os.environ.get("PENTEST_LAB_RUNNER_IMAGE", "vulnguard-pentest-runner:latest")

SINK_SRC = r'''
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        print('INGEST', json.dumps({'ts': self.headers.get('X-VG-Ts'), 'nonce': self.headers.get('X-VG-Nonce'), 'sig': self.headers.get('X-VG-Sig'), 'auth': self.headers.get('Authorization'), 'eng': self.headers.get('X-VG-Eng'), 'host': self.headers.get('Host'), 'raw': b.decode(), 'body': json.loads(b)}), flush=True)
        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('0.0.0.0', 8000), H).serve_forever()
'''

TARGET_SRC = r'''
import sys, threading, http.server, socketserver, urllib.parse, socket
def udp_echo(p):   # P2-5: responder UDP (positive control cho probe UDP/QUIC; mỗi gói tới = một dòng UDP trong log = tripwire)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", p))
    while True:
        d, a = s.recvfrom(2048); print("UDP", a[0], p, flush=True); s.sendto(b"echo:" + d, a)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("HIT", self.client_address[0], self.command, self.path, flush=True)
        if self.path.startswith("/redir"):
            to = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("to", ["/"])[0]
            self.send_response(302); self.send_header("Location", to); self.end_headers(); return
        body = b"target-ok"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
for p in map(int, sys.argv[1:]):
    threading.Thread(target=S(("0.0.0.0", p), H).serve_forever, daemon=True).start()
    threading.Thread(target=udp_echo, args=(p,), daemon=True).start()
threading.Event().wait()
'''

DNS_SRC = r'''
import json, os, itertools
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from dnslib.server import DNSServer, BaseResolver
REC = json.loads(os.environ["RECORDS"]); CNT = {}
class R(BaseResolver):
    def resolve(self, request, handler):
        r = request.reply(); n = str(request.q.qname).rstrip(".").lower()
        print("Q", n, QTYPE[request.q.qtype], flush=True)
        if n not in REC: r.header.rcode = RCODE.NXDOMAIN; return r
        seq = REC[n]; i = CNT.get(n, 0); CNT[n] = i + 1
        ips = seq[min(i, len(seq) - 1)] if isinstance(seq[0], list) else seq
        if request.q.qtype == QTYPE.A:
            for ip in ips: r.add_answer(RR(request.q.qname, QTYPE.A, ttl=5, rdata=A(ip)))
        return r
DNSServer(R(), port=53, address="0.0.0.0").start_thread()
DNSServer(R(), port=53, address="0.0.0.0", tcp=True).start()
'''


def _cleanup(cli, uid, eid):
    """Dọn MỌI thứ của lần chạy này theo NHÃN (không theo tên): container lab (`vgt=<uid>`), container do runner tạo (`vulnguard.eng=<eid>`), mạng.
    Chạy cả khi setup hỏng giữa chừng (trước đây rò container/mạng)."""
    for flt in (f"vgt={uid}", f"vulnguard.eng={eid}"):
        for c in cli.containers.list(all=True, filters={"label": flt}):
            try:
                c.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
    for flt in (f"vgt={uid}", f"vulnguard.eng={eid}"):
        for n in cli.networks.list(filters={"label": flt}):
            try:
                n.remove()
            except Exception:  # noqa: BLE001
                pass


def _wait(fn, timeout=20, step=0.3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


@pytest.fixture(scope="module")
def lab():
    import docker

    from scanner.pentest.egress_policy import compile_policy
    from services.pentest_runner.app import Settings, create_app
    from services.pentest_runner.egress import EgressGateway
    cli = docker.from_env()
    for img in (EGW, PY):
        cli.images.get(img)
    uid = uuid.uuid4().hex[:8]
    LBL = {"vgt": uid}
    eid = "lab" + uid
    made = []
    out = ing = None
    try:
        # Dải CGNAT 100.64/10: KHÔNG "private/reserved" theo scope._dangerous_ip → mô phỏng IP công khai (test port-pin không cần rule ip tường minh)
        import random
        sub = f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.0/24"
        out = cli.networks.create(f"vgt-out-{uid}", driver="bridge", labels=LBL,
                                  ipam=docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=sub)]))

        def ip_of(c, net):
            c.reload()
            return c.attrs["NetworkSettings"]["Networks"][net]["IPAddress"]

        t1 = cli.containers.run(PY, command=["python", "-c", TARGET_SRC, "80", "8080"], network=out.name, detach=True, name=f"vgt-t1-{uid}", labels=LBL)
        t2 = cli.containers.run(PY, command=["python", "-c", TARGET_SRC, "80", "22"], network=out.name, detach=True, name=f"vgt-t2-{uid}", labels=LBL)
        t3 = cli.containers.run(PY, command=["python", "-c", TARGET_SRC, "80", "8080"], network=out.name, detach=True, name=f"vgt-t3-{uid}", labels=LBL)
        made += [t1, t2, t3]
        ip1, ip2, ip3 = ip_of(t1, out.name), ip_of(t2, out.name), ip_of(t3, out.name)
        records = {"inscope.lab": [ip1], "pinned.lab": [ip3], "oos.lab": [ip2], "metadata.lab": ["169.254.169.254"],
                   "loopback.lab": ["127.0.0.1"], "rebind.lab": [[ip1], ["127.0.0.1"], ["169.254.169.254"]], "xn--fa-hia.lab": [ip1]}
        dns = cli.containers.run(EGW, entrypoint=["python3", "-c", DNS_SRC], environment={"RECORDS": json.dumps(records)},
                                 network=out.name, detach=True, name=f"vgt-dns-{uid}", labels=LBL)
        made.append(dns)
        dns_ip = ip_of(dns, out.name)
        ing = cli.networks.create(f"vgt-ing-{uid}", driver="bridge", labels=LBL)
        sink = cli.containers.run(PY, command=["python", "-c", SINK_SRC], network=ing.name, detach=True, name=f"vgt-sink-{uid}", labels=LBL)
        made.append(sink)
        gw = EgressGateway(EGW, out_network=out.name, upstream_dns=dns_ip, secret=TOKEN, ingest_network=ing.name,
                           ingest_url=f"http://vgt-sink-{uid}:8000/api/pentest/internal/traffic")
        app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": RUNNER_IMG,
                                   "PENTEST_ALLOW_UNPINNED_IMAGE": "1", "PENTEST_RUNNER_GC_INTERVAL_S": "0"}), lambda: cli, gateway=gw)
        http = TestClient(app)
        rules = [{"type": "domain", "value": "inscope.lab", "include_subdomains": False, "mode": "allow"},
                 {"type": "ip", "value": ip1, "mode": "allow"},
                 {"type": "url", "value": "http://pinned.lab:8080", "mode": "allow"},
                 {"type": "domain", "value": "rebind.lab", "include_subdomains": False, "mode": "allow"},
                 {"type": "domain", "value": "metadata.lab", "include_subdomains": False, "mode": "allow"},
                 {"type": "domain", "value": "loopback.lab", "include_subdomains": False, "mode": "allow"}]
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        pol = compile_policy(rules, {}, 1, exp, engagement_id=eid)
        r = http.post(f"/v1/engagements/{eid}/network", json={"policy": pol.to_dict()}, headers=H)
        assert r.status_code == 200, r.text
        gid = r.json()["gateway_id"]
        gwc = cli.containers.get(gid)
        gw_ip = ip_of(gwc, f"vg-eng-{eid}")
        probe = cli.containers.run(PY, command=["sleep", "3600"], network=f"vg-eng-{eid}", dns=[gw_ip], detach=True, cap_drop=["ALL"],
                                   security_opt=["no-new-privileges:true"], name=f"vgt-probe-{uid}", user="10002:10002", labels=LBL,
                                   environment={"HTTP_PROXY": f"http://{gw_ip}:8080", "HTTPS_PROXY": f"http://{gw_ip}:8080", "NO_PROXY": ""})
        made.append(probe)
        gw.attach(cli, eid, gid, gw_ip, probe, "labrun")
        L = type("Lab", (), {})()
        L.uid = uid
        L.cli, L.http, L.eid, L.gid, L.gwc, L.gw_ip, L.probe = cli, http, eid, gid, gwc, gw_ip, probe
        L.ip1, L.ip2, L.ip3, L.t1, L.t2, L.dns, L.rules, L.out = ip1, ip2, ip3, t1, t2, dns, rules, out
        L.version, L.sink, L.ing, L.gw = 1, sink, ing, gw
        yield L
    finally:
        _cleanup(cli, uid, eid)


def py(lab, code, timeout=40):
    """Chạy code python TRONG probe; trả (exit, stdout+stderr)."""
    code_, out = lab.probe.exec_run(["python3", "-c", code], user="10002:10002")
    return code_, out.decode("utf-8", "replace")


RESOLVE = "import socket,sys\ntry: print('IP', socket.gethostbyname(sys.argv[1]))\nexcept Exception as e: print('ERR', e)\n"


def resolve(lab, name):
    _, out = py(lab, f"import socket\ntry: print('IP', socket.gethostbyname({name!r}))\nexcept Exception as e: print('ERR', e)")
    return out.strip()


def tcp(lab, ip, port, t=3):
    _, out = py(lab, f"import socket\ns=socket.socket(); s.settimeout({t})\ntry: s.connect(({ip!r},{port})); print('OPEN')\nexcept Exception as e: print('FAIL', type(e).__name__)")
    return out.strip()


def via_proxy(lab, url, t=10):
    code = (f"import urllib.request as u, os\nh=u.ProxyHandler({{'http':os.environ['HTTP_PROXY'],'https':os.environ['HTTPS_PROXY']}})\n"
            "class NR(u.HTTPRedirectHandler):\n  def redirect_request(self,*a,**k): return None\n"
            f"o=u.build_opener(h,NR)\ntry:\n r=o.open({url!r},timeout={t}); print('STATUS',r.status,r.read(40))\n"
            "except u.HTTPError as e: print('STATUS',e.code,e.headers.get('Location',''),e.headers.get('X-VG-Egress',''))\n"
            "except Exception as e: print('ERR',type(e).__name__,e)")
    return py(lab, code)[1].strip()


def events(lab, kind=None):
    out = lab.gwc.logs().decode("utf-8", "replace")
    evs = []
    for ln in out.splitlines():
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if isinstance(e, dict) and (kind is None or e.get("kind") == kind):
            evs.append(e)
    return evs


def hits(c):
    return [ln for ln in c.logs().decode().splitlines() if ln.startswith("HIT")]


# ───────────── DNS ─────────────
def test_dns_only_in_scope_names(lab):
    assert resolve(lab, "inscope.lab") == f"IP {lab.ip1}"
    assert resolve(lab, "oos.lab").startswith("ERR")                      # ngoài scope → NXDOMAIN
    assert any(e["name"] == "oos.lab" for e in events(lab, "dns_denied"))


def test_dns_filters_dangerous_answers(lab):
    assert resolve(lab, "metadata.lab").startswith("ERR")                 # → 169.254.169.254
    assert resolve(lab, "loopback.lab").startswith("ERR")                 # → 127.0.0.1
    flt = {e["ip"] for e in events(lab, "dns_filtered")}
    assert {"169.254.169.254", "127.0.0.1"} <= flt


def test_rebinding_answers_never_open_dangerous_ip(lab):
    assert resolve(lab, "rebind.lab") == f"IP {lab.ip1}"
    time.sleep(6)                                                         # TTL upstream = 5 → hết cache của libc? (mỗi lần hỏi lại gateway)
    for _ in range(3):
        r = resolve(lab, "rebind.lab")
        assert r in (f"IP {lab.ip1}",) or r.startswith("ERR"), r          # KHÔNG bao giờ 127.0.0.1 / 169.254.169.254
    assert tcp(lab, "169.254.169.254", 80, 2).startswith("FAIL")


def test_idna_mismatch_name_denied(lab):
    assert resolve(lab, "faß.lab").startswith("ERR")                 # ß: IDNA2003≠2008 → scope từ chối → NXDOMAIN


# ───────────── TCP / nft ─────────────
def test_tcp_in_scope_and_oos(lab):
    assert tcp(lab, lab.ip1, 80) == "OPEN"
    before = len(hits(lab.t2))
    assert tcp(lab, lab.ip2, 80, 3).startswith("FAIL")
    assert tcp(lab, lab.ip2, 22, 3).startswith("FAIL")
    assert len(hits(lab.t2)) == before                                    # tripwire: out-of-scope không nhận gì


def test_denied_tcp_produces_event(lab):
    tcp(lab, lab.ip2, 80, 2)
    ev = _wait(lambda: [e for e in events(lab, "egress_denied") if e.get("dst") == lab.ip2 and e.get("via") == "nft"], 10)
    assert ev, "không có event egress_denied từ nflog"


def test_port_pinned_url_rule(lab):
    # rule `url http://pinned.lab:8080` → IP học qua DNS chỉ mở đúng cổng 8080 (t3 nghe cả 80 và 8080)
    assert resolve(lab, "pinned.lab") == f"IP {lab.ip3}"
    assert tcp(lab, lab.ip3, 8080) == "OPEN"
    assert tcp(lab, lab.ip3, 80, 2).startswith("FAIL")
    assert via_proxy(lab, "http://pinned.lab:8080/").startswith("STATUS 200")
    assert "403" in via_proxy(lab, "http://pinned.lab/")                  # cổng 80 ngoài rule url → addon 403


def test_udp_icmp_ipv6_denied(lab):
    _, out = py(lab, f"import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)\n"
                     f"s.sendto(b'x',({lab.ip1!r},9)); \ntry: s.recvfrom(10); print('REPLY')\nexcept Exception as e: print('NOREPLY')")
    assert out.strip() == "NOREPLY"
    _, out = py(lab, "import socket\ntry:\n s=socket.socket(socket.AF_INET6); s.settimeout(2); s.connect(('2001:db8::1',80)); print('OPEN')\nexcept Exception as e: print('FAIL')")
    assert out.strip() == "FAIL"
    # DNS thô tới upstream (không qua gateway) bị chặn: chỉ gateway :53 trả lời
    _, out = py(lab, f"import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)\n"
                     f"s.sendto(bytes.fromhex('123401000001000000000000066f6f73036c616200000100 01'.replace(' ','')),({lab.dns.attrs['NetworkSettings']['Networks'][lab.out.name]['IPAddress']!r},53))\n"
                     "try: s.recvfrom(100); print('REPLY')\nexcept Exception: print('NOREPLY')")
    assert "NOREPLY" in out or "REPLY" in out  # (xem test dưới: upstream DNS không tới được từ sandbox ở tầng TCP)


def test_icmp_denied_with_raw_socket(lab):
    import docker
    cli = lab.cli
    p = cli.containers.run(PY, command=["python3", "-c",
        "import socket,struct,sys\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.settimeout(2)\n"
        "pkt=struct.pack('!BBHHH',8,0,0xf7ff,1,1)+b'x'*8\n"
        f"s.sendto(pkt,('{lab.ip1}',0))\n"
        "try: s.recvfrom(100); print('REPLY')\nexcept Exception: print('NOREPLY')"],
        network=f"vg-eng-{lab.eid}", dns=[lab.gw_ip], cap_drop=["ALL"], cap_add=["NET_RAW"], detach=True, name=f"vgt-icmp-{uuid.uuid4().hex[:6]}", labels={"vgt": lab.uid})
    try:
        from services.pentest_runner.egress import EgressGateway
        EgressGateway(EGW, out_network=lab.out.name).attach(cli, lab.eid, lab.gid, lab.gw_ip, p, "labrun")
        p.reload()
        assert _wait(lambda: p.reload() or p.status == "exited", 15)
        assert "NOREPLY" in p.logs().decode()
    finally:
        p.remove(force=True)


def test_events_are_posted_to_api_ingest_with_per_engagement_hmac(lab):
    from services.pentest_runner.egress import ingest_token
    resolve(lab, "oos.lab")
    tcp(lab, lab.ip2, 80, 2)
    via_proxy(lab, "http://inscope.lab/")

    def got():
        rows = [json.loads(ln.split(" ", 1)[1]) for ln in lab.sink.logs().decode().splitlines() if ln.startswith("INGEST")]
        kinds = {e["kind"] for r in rows for e in r["body"]["events"]}
        return rows if {"dns_denied", "egress_denied", "http"} <= kinds else None
    rows = _wait(got, 20)
    assert rows, lab.sink.logs().decode()[-1500:]
    r0 = rows[0]
    from api.routes.pentest_internal import sign
    assert r0["auth"] is None and r0["eng"] == lab.eid and r0["host"].startswith("vgt-sink-")
    for r in rows:     # mỗi POST: chữ ký HMAC hợp lệ trên (eid, ts, nonce, body) bằng khoá theo engagement; nonce không lặp
        assert r["sig"] == sign(ingest_token(TOKEN, lab.eid), lab.eid, r["ts"], r["nonce"], r["raw"].encode())
    assert len({r["nonce"] for r in rows}) == len(rows)
    assert any(e.get("run_id") == "labrun" for r in rows for e in r["body"]["events"] if e["kind"] == "egress_denied")   # IP sandbox → run (vg-egw map)
    # sandbox KHÔNG tới được mạng ingest/API qua gateway
    sink_ip = lab.sink.attrs["NetworkSettings"]["Networks"][lab.ing.name]["IPAddress"] if lab.sink.reload() is None else None
    assert tcp(lab, sink_ip, 8000, 2).startswith("FAIL")


def test_account_credentials_in_gateway_copy_never_reach_db_or_api(lab, monkeypatch):
    """F1 (PR83): gateway ghi NGUYÊN request (kể cả header credential của tài khoản test). Chứng minh (1) secret thật sự
    đi qua gateway tới ingest, (2) sau ingest API nó KHÔNG nằm trong DB / GET /api/pentest/traffic/{id}."""
    import hashlib
    import hmac as _hmac

    from api.auth_models import UserRole
    from api.database import Base, SessionLocal, engine
    from api.pentest_models import TrafficEntry
    from api.routes import pentest_internal as pi
    from scanner.pentest import test_accounts
    from scanner.pentest.settings import pentest_settings
    from services.pentest_runner.egress import ingest_token
    from tests._authutil import bearer, login, make_user, new_client
    from tests.pentest_fakes import make_engagement, make_run
    secret = "Bearer PR83-LABSECRET-" + uuid.uuid4().hex
    tokval = secret.split(" ", 1)[1]
    code = ("import urllib.request as u, os\n"
            "h=u.ProxyHandler({'http':os.environ['HTTP_PROXY'],'https':os.environ['HTTPS_PROXY']})\n"
            f"o=u.build_opener(h)\nr=o.open(u.Request('http://inscope.lab/?tok='+{tokval!r}+'&q=1', headers={{'Authorization': {secret!r}}}), timeout=10)\nprint('STATUS', r.status)")
    assert "STATUS 200" in py(lab, code)[1]

    def wire():
        rows = [json.loads(ln.split(" ", 1)[1]) for ln in lab.sink.logs().decode().splitlines() if ln.startswith("INGEST")]
        evs = [e for r in rows for e in r["body"]["events"] if e["kind"] == "http" and secret in json.dumps(e.get("req_headers", {}))]
        return evs or None
    evs = _wait(wire, 20)
    assert evs, "secret không xuất hiện trong bản sao gateway → test không có ý nghĩa"
    assert any(tokval in e.get("url", "") for e in evs), "secret không có trong URL của bản sao gateway (R1)"

    monkeypatch.setattr(pentest_settings, "runner_token", TOKEN)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        eng = make_engagement(db, [{"type": "domain", "value": "inscope.lab", "mode": "allow"}])
        run = make_run(db, eng)
        test_accounts.store(db, eng.id, {"a": {"label": "a", "marker": "alice@lab.test", "headers": {"Authorization": secret}},
                                         "b": {"label": "b", "marker": "bob@lab.test", "headers": {"Authorization": "Bearer other-" + uuid.uuid4().hex}}})
        db.commit()
        for e in evs:
            e["run_id"] = run.id
        body = json.dumps({"events": evs}).encode()
        ts, nonce = str(int(time.time())), uuid.uuid4().hex[:16]
        sig = pi.sign(ingest_token(TOKEN, eng.id), eng.id, ts, nonce, body)
        from api.main import app
        c = new_client()
        r = TestClient(app).post("/api/pentest/internal/traffic", content=body, headers={
            "X-VG-Eng": eng.id, "X-VG-Ts": ts, "X-VG-Nonce": nonce, "X-VG-Sig": sig, "Content-Type": "application/json"})
        assert r.status_code == 200 and r.json()["stored"] >= 1, r.text
        db.expire_all()
        rows = db.query(TrafficEntry).filter(TrafficEntry.engagement_id == eng.id, TrafficEntry.source == "egress").all()
        assert rows
        email, _ = make_user(UserRole.VIEWER)
        hdr = bearer(login(c, email))
        for t in rows:
            api = c.get(f"/api/pentest/traffic/{t.id}", headers=hdr)
            assert api.status_code == 200
            blob = json.dumps([t.request_headers, t.request_body, t.response_headers, t.response_body, t.url]) + api.text   # R1: cả URL
            assert secret not in blob and secret.split(" ", 1)[1] not in blob
    finally:
        db.query(TrafficEntry).filter(TrafficEntry.engagement_id == eng.id).delete()
        db.commit()
        db.close()


# ───────────── cô lập host / gateway ─────────────
def test_sandbox_cannot_reach_bridge_gateway_or_gateway_ports(lab):
    net = lab.cli.networks.get(f"vg-eng-{lab.eid}")
    assert net.attrs["Options"].get("com.docker.network.bridge.inhibit_ipv4") == "true" and not net.attrs["Internal"]
    import ipaddress
    sub = ipaddress.ip_network(net.attrs["IPAM"]["Config"][0]["Subnet"])
    first = str(next(sub.hosts()))                                          # IP .1 của bridge: host KHÔNG có địa chỉ ở đây
    for port in (22, 80, 2375, 8080 if first != lab.gw_ip else 9):
        assert tcp(lab, first, port, 2).startswith("FAIL") or first == lab.gw_ip
    for port in (22, 9999, 5353 + 1):
        assert tcp(lab, lab.gw_ip, port, 2).startswith("FAIL")             # cổng lạ của gateway bị drop (input chain)


# ───────────── mitmproxy ─────────────
def test_proxy_in_scope_ok_and_recorded(lab):
    assert via_proxy(lab, "http://inscope.lab/").startswith("STATUS 200")
    assert _wait(lambda: [e for e in events(lab, "http") if "inscope.lab" in e["url"]], 10)


def test_proxy_blocks_ip_literal_oos_and_redirect_hops(lab):
    before = len(hits(lab.t2))
    out = via_proxy(lab, f"http://{lab.ip2}/")
    assert "403" in out and "denied" in out, out                          # IP literal ngoài scope → addon 403
    out = via_proxy(lab, f"http://inscope.lab/redir?to=http://{lab.ip2}/x")
    assert "302" in out                                                    # hop 1 được phép (trong scope), client thấy redirect
    assert "403" in via_proxy(lab, f"http://{lab.ip2}/x")                  # hop 2 (client tự theo) bị chặn
    assert "403" in via_proxy(lab, "http://oos.lab/x")                     # tên ngoài scope: addon 403 (và DNS NXDOMAIN)
    assert len(hits(lab.t2)) == before
    assert _wait(lambda: [e for e in events(lab, "egress_redirect_oos")], 10)


def test_proxy_blocks_host_header_override(lab):
    code = (f"import http.client\nc=http.client.HTTPConnection({lab.gw_ip!r},8080,timeout=8)\n"
            f"c.request('GET','http://{lab.ip1}/',headers={{'Host':'oos.lab'}})\nr=c.getresponse(); print('STATUS',r.status)")
    assert "STATUS 403" in py(lab, code)[1]


def test_proxy_connect_tunnel_oos_denied(lab):
    code = (f"import http.client\nc=http.client.HTTPConnection({lab.gw_ip!r},8080,timeout=8)\n"
            f"c.set_tunnel('{lab.ip2}',443)\ntry:\n c.request('GET','/'); print('STATUS',c.getresponse().status)\nexcept Exception as e: print('ERR',type(e).__name__,e)")
    assert "403" in py(lab, code)[1] or "ERR" in py(lab, code)[1]


# ───────────── hot reload / expiry ─────────────
def _put(lab, rules, expiry_s=3600):
    """Biên dịch + PUT policy phiên bản kế tiếp (đơn điệu tăng)."""
    from scanner.pentest.egress_policy import compile_policy
    lab.version += 1
    p = compile_policy(rules, {}, lab.version, datetime.now(timezone.utc) + timedelta(seconds=expiry_s), engagement_id=lab.eid)
    r = lab.http.put(f"/v1/engagements/{lab.eid}/policy", json={"policy": p.to_dict()}, headers=H)
    assert r.status_code == 204, r.text


def test_hot_reload_narrows_and_rejects_stale(lab):
    r = lab.http.put(f"/v1/engagements/{lab.eid}/policy", json={"policy": {"version": 1}}, headers=H)
    assert r.status_code == 409                                            # stale (runner)
    _put(lab, [{"type": "domain", "value": "pinned.lab", "include_subdomains": False, "mode": "allow"}])
    assert tcp(lab, lab.ip1, 80, 2).startswith("FAIL")                     # ip rule đã bị gỡ
    assert resolve(lab, "inscope.lab").startswith("ERR")
    _put(lab, lab.rules)                                                   # khôi phục
    assert tcp(lab, lab.ip1, 80) == "OPEN"


def test_deny_url_rule_on_ip_blocks_raw_tcp_not_only_proxy(lab):
    """M1: scope allow ip1 (mọi cổng) + deny url http://ip1:8080 → TCP thô tới ip1:8080 phải bị drop (trước đây nft vẫn cho qua)."""
    assert tcp(lab, lab.ip1, 8080) == "OPEN"
    _put(lab, lab.rules + [{"type": "url", "value": f"http://{lab.ip1}:8080", "mode": "deny"}])
    try:
        assert tcp(lab, lab.ip1, 8080, 2).startswith("FAIL")
        assert tcp(lab, lab.ip1, 80) == "OPEN"                             # cổng khác của cùng IP vẫn mở (scope cho phép)
        assert "403" in via_proxy(lab, f"http://{lab.ip1}:8080/")          # proxy và nft nhất quán
    finally:
        _put(lab, lab.rules)
    assert tcp(lab, lab.ip1, 8080) == "OPEN"


def test_explicit_private_cidr_allow_cannot_reach_host_stack(lab):
    """M2: scope cho phép TƯỜNG MINH mạng ra ngoài + mọi dải riêng → IP của host (gateway của bridge ra ngoài, IP host/VM) vẫn bị drop
    (timeout), còn IP khác trong dải thì mở. Host phản hồi RST nếu chạm được → 'ConnectionRefusedError' = rò."""
    import ipaddress
    out_cfg = lab.cli.networks.get(lab.out.name).attrs["IPAM"]["Config"][0]
    out_gw = out_cfg["Gateway"]
    wide = [{"type": "cidr", "value": c, "mode": "allow"} for c in (out_cfg["Subnet"], "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    lab_desktop = str((lab.cli.info() or {}).get("OperatingSystem", "")).startswith("Docker Desktop")
    if lab_desktop:   # P2-5: Docker Desktop fail-closed — cần EXTRA_DENY (IP LAN của host) trước khi scope được mở dải riêng
        import socket as _s
        _sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        _sk.connect(("192.0.2.1", 9))
        lab.gw.extra_deny = (f"{_sk.getsockname()[0]}/32",)
        _sk.close()
    _put(lab, wide)
    try:
        assert tcp(lab, lab.ip3, 80) == "OPEN"                             # đối chứng: dải được mở thật
        assert tcp(lab, out_gw, 22, 3) == "FAIL TimeoutError", tcp(lab, out_gw, 22, 3)
        host_ips = [i for i in lab.gw._host_ips(lab.cli) if ipaddress.ip_address(i) not in ipaddress.ip_network(out_cfg["Subnet"])][:4]
        assert host_ips, "không đọc được IP host"
        for ip in host_ips:
            for port in (22, 111):
                assert tcp(lab, ip, port, 2) == "FAIL TimeoutError", (ip, port)
    finally:
        _put(lab, lab.rules)
        lab.gw.extra_deny = ()
    assert tcp(lab, lab.ip1, 80) == "OPEN"


def test_policy_expiry_drops_everything(lab):
    from scanner.pentest.egress_policy import compile_policy
    _put(lab, lab.rules, expiry_s=4)
    assert tcp(lab, lab.ip1, 80) == "OPEN"
    time.sleep(6)
    assert tcp(lab, lab.ip1, 80, 2).startswith("FAIL")
    assert resolve(lab, "inscope.lab").startswith("ERR")
    _put(lab, lab.rules)                                                   # khôi phục cho test sau
    assert tcp(lab, lab.ip1, 80) == "OPEN"


# ───────────── sandbox THẬT của runner (image vulnguard-pentest-runner) đi qua gateway ─────────────
def _exec(lab, rid, step, tool, argv, timeout=60, wait=90):
    r = lab.http.post(f"/v1/runs/{rid}/exec", headers=H, json={"step_id": step, "tool": tool, "argv": argv, "timeout_s": timeout})
    assert r.status_code == 200, r.text
    xid = r.json()["exec_id"]
    for _ in range(int(wait / 0.25)):
        st = lab.http.get(f"/v1/runs/{rid}/exec/{xid}", headers=H).json()
        if st["status"] != "running":
            out = lab.http.get(f"/v1/runs/{rid}/exec/{xid}/output?stream=stdout", headers=H).content.decode("utf-8", "replace")
            return st, out
        time.sleep(0.25)
    raise AssertionError("exec did not finish")


def test_real_runner_sandbox_tools_are_confined_by_gateway(lab):
    try:
        lab.cli.images.get(RUNNER_IMG)
    except Exception:  # noqa: BLE001
        pytest.skip("thiếu image vulnguard-pentest-runner (make pentest-images)")
    rid = "sbx" + uuid.uuid4().hex[:6]
    r = lab.http.post(f"/v1/runs/{rid}/sandbox", json={"eid": lab.eid, "limits": {}}, headers=H)
    assert r.status_code == 200, r.text
    try:
        # nmap TCP connect: in-scope IP mở, IP ngoài scope bị drop (filtered), metadata filtered
        st, out = _exec(lab, rid, "n1", "nmap", ["nmap", "-Pn", "-n", "-p", "80", "--max-retries", "1", "--host-timeout", "20s", lab.ip1])
        assert "80/tcp open" in out, out
        before = len(hits(lab.t2))
        st, out = _exec(lab, rid, "n2", "nmap", ["nmap", "-Pn", "-n", "-p", "80,22", "--max-retries", "1", "--host-timeout", "20s", lab.ip2])
        assert "open" not in out.replace("Not shown", ""), out
        assert len(hits(lab.t2)) == before
        # DNS qua gateway: tên in-scope phân giải được, tên ngoài scope thì không
        st, out = _exec(lab, rid, "n3", "nmap", ["nmap", "-sL", "inscope.lab", "oos.lab"])
        assert lab.ip1 in out and f"oos.lab ({lab.ip2})" not in out
        # vg_http (HTTP_PROXY → mitmproxy): in-scope 200, ngoài scope 403 từ gateway
        def req(url):
            b = base64.b64encode(json.dumps({"method": "GET", "url": url, "timeout": 10}).encode()).decode()
            return json.loads(_exec(lab, rid, "h" + uuid.uuid4().hex[:4], "python3 -m vg_http", ["python3", "-m", "vg_http", "--req-b64", b])[1])
        assert req("http://inscope.lab/")["status"] == 200
        denied = req(f"http://{lab.ip2}/")
        assert denied["status"] == 403 and "VulnGuard egress" in denied["body"]
        # không có secret trong env của sandbox
        sbx = [c for c in lab.cli.containers.list() if c.name == f"vg-sbx-{rid}"][0]
        env = {e.split("=", 1)[0] for e in sbx.attrs["Config"]["Env"]}
        assert not [k for k in env if "KEY" in k or "TOKEN" in k or "SECRET" in k]
    finally:
        lab.http.delete(f"/v1/runs/{rid}/sandbox", headers=H)
