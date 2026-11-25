"""Runner phía host: điều khiển lab Docker và chạy kịch bản. KHÔNG bao giờ chạm host ngoài lab.

  run_scenario(s) -> dict(status = pass | fail | error | pending, ...)
`error` = hạ tầng/kịch bản hỏng nên KHÔNG kết luận được (luôn đỏ ở CI) — không bao giờ được tính là pass.

Điều kiện an toàn (kiểm TRƯỚC khi chạy): scope/target ⊂ 172.31.250.0/24 (trừ .0/.1/.255) hoặc *.lab; compose + container ĐANG CHẠY
(docker inspect) không privileged / cap lạ / host network / docker.sock; network internal + gateway isolated; probe gateway.
Canary trước & sau mỗi kịch bản chứng minh DNS / tripwire / sniffer / inscope-web còn sống (hạ tầng chết ⇒ error, không phải pass).
"""
import ipaddress
import json
import os
import subprocess  # nosec B404 — chỉ gọi `docker` với argv cố định
import time
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from eval.harness import metrics as M
from eval.harness.scenarios import LAB_GATEWAY, LAB_NET, Scenario

COMPOSE_FILE = os.path.join(os.path.dirname(__file__), "..", "lab", "docker-compose.lab.yml")
VG = "vg-under-test"
TRIPWIRES = ["lab-oos", "lab-metadata"]
INSCOPE = "lab-inscope"
DNS = "lab-dns"
CAPTURE = "lab-capture"
LAB_CONTAINERS = [VG, INSCOPE, DNS, CAPTURE] + TRIPWIRES
GW_OPT = "com.docker.network.bridge.gateway_mode_ipv4"
TOOLS = ["nmap", "ffuf", "nuclei", "sqlmap"]


class LabSafetyError(RuntimeError):
    pass


# ── Bất biến an toàn (thuần, test được) ──
def _lab_ip(ip) -> bool:
    net = ipaddress.ip_network(LAB_NET)
    return ip in net and str(ip) not in (str(net.network_address), LAB_GATEWAY, str(net.broadcast_address))


def _host_ok(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    try:
        return _lab_ip(ipaddress.ip_address(host))
    except ValueError:
        return host == "lab" or host.endswith(".lab")


def _value_host(value: str) -> str:
    u = urlsplit(value if "://" in value else "//" + value)
    return u.hostname or ""


def assert_scenario_safe(s: Scenario) -> None:
    for r in s.scope_rules:
        v = (r.get("value") or "").strip()
        if r.get("type") == "cidr":
            try:
                n = ipaddress.ip_network(v, strict=False)
                ok = n.subnet_of(ipaddress.ip_network(LAB_NET)) and ipaddress.ip_address(LAB_GATEWAY) not in n
            except ValueError:
                ok = False
        else:
            ok = _host_ok(_value_host(v))
        if not ok:
            raise LabSafetyError(f"{s.id}: scope rule ngoài lab: {r}")
    for t in s.targets:
        if not _host_ok(_value_host(t)):
            raise LabSafetyError(f"{s.id}: seed target ngoài lab: {t}")
    for ip in s.allowed_ips:
        if not _host_ok(ip):
            raise LabSafetyError(f"{s.id}: allowed_ips ngoài lab: {ip}")


def assert_compose_safe(cfg: Dict) -> None:
    """cfg = `docker compose config --format json` (hoặc YAML đã parse)."""
    nets = cfg.get("networks") or {}
    for n in ("lab_net", "oos_net"):
        net = nets.get(n) or {}
        if net.get("internal") is not True:
            raise LabSafetyError(f"network {n} thiếu `internal: true`")
        if (net.get("driver_opts") or {}).get(GW_OPT) != "isolated":
            raise LabSafetyError(f"network {n} thiếu gateway_mode_ipv4=isolated (host reachable qua gateway)")
    svcs = cfg.get("services") or {}
    vg = svcs.get("vg-under-test") or {}
    if set((vg.get("networks") or {}).keys()) != {"lab_net"}:
        raise LabSafetyError("vg-under-test phải chỉ nối lab_net")
    for name, svc in svcs.items():
        if svc.get("ports"):
            raise LabSafetyError(f"service {name} không được publish port ra host")
        if svc.get("privileged") or svc.get("network_mode") == "host" or svc.get("pid") == "host":
            raise LabSafetyError(f"service {name}: privileged/host network/pid bị cấm")
        if any("docker.sock" in str(v) for v in (svc.get("volumes") or [])):
            raise LabSafetyError(f"service {name}: không được mount docker.sock")
        caps = set(svc.get("cap_add") or [])
        if caps and not (name == "capture" and caps == {"NET_RAW"}):
            raise LabSafetyError(f"service {name}: cap_add {sorted(caps)} không được phép")
        if name != "capture" and svc.get("network_mode"):
            raise LabSafetyError(f"service {name}: network_mode không được phép")
    if (svcs.get("capture") or {}).get("network_mode") != "service:vg-under-test":
        raise LabSafetyError("capture phải chung netns với vg-under-test")


def assert_live_safe(inspects: List[Dict], networks: List[Dict]) -> None:
    """inspects = `docker inspect <containers>`; networks = `docker network inspect <networks>` (trạng thái ĐANG CHẠY)."""
    names = {i.get("Name", "").lstrip("/") for i in inspects}
    missing = set(LAB_CONTAINERS) - names
    if missing:
        raise LabSafetyError(f"container lab không chạy: {sorted(missing)}")
    for i in inspects:
        name, hc = i.get("Name", "").lstrip("/"), i.get("HostConfig") or {}
        if not (i.get("State") or {}).get("Running"):
            raise LabSafetyError(f"{name} không ở trạng thái running")
        if hc.get("Privileged"):
            raise LabSafetyError(f"{name}: Privileged")
        caps = {c.upper().removeprefix("CAP_") for c in (hc.get("CapAdd") or [])}
        if caps and not (name == CAPTURE and caps == {"NET_RAW"}):
            raise LabSafetyError(f"{name}: CapAdd {sorted(caps)}")
        mode = hc.get("NetworkMode") or ""
        if mode == "host" or (mode.startswith("container:") and name != CAPTURE):
            raise LabSafetyError(f"{name}: NetworkMode {mode}")
        if hc.get("PidMode") == "host":
            raise LabSafetyError(f"{name}: PidMode host")
        for m in i.get("Mounts") or []:
            if "docker.sock" in str(m.get("Source", "")) or "docker.sock" in str(m.get("Destination", "")):
                raise LabSafetyError(f"{name}: mount docker.sock")
    attached = {n for i in inspects for n in ((i.get("NetworkSettings") or {}).get("Networks") or {})}
    by_name = {n.get("Name"): n for n in networks}
    for n in attached:
        net = by_name.get(n)
        if net is None:
            raise LabSafetyError(f"network {n} không inspect được")
        if net.get("Internal") is not True:
            raise LabSafetyError(f"network {n} không internal")
        if net.get("EnableIPv6"):
            raise LabSafetyError(f"network {n} bật IPv6")
        if (net.get("Options") or {}).get(GW_OPT) != "isolated":
            raise LabSafetyError(f"network {n}: gateway_mode_ipv4 != isolated (host reachable qua {LAB_GATEWAY})")
    vg = next(i for i in inspects if i.get("Name", "").lstrip("/") == VG)
    if set(((vg.get("NetworkSettings") or {}).get("Networks") or {}).keys()) != {n for n in attached if n.endswith("lab_net")}:
        raise LabSafetyError("vg-under-test phải chỉ nối lab_net")


# ── Docker helpers ──
def _docker(args: List[str], inp: Optional[str] = None, timeout: int = 300) -> str:
    p = subprocess.run(["docker"] + args, input=inp, capture_output=True, text=True, timeout=timeout)  # nosec B603 B607
    if p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} lỗi: {p.stderr[-500:]}")
    return p.stdout


def _py(container: str, code: str, timeout: int = 60) -> str:
    return _docker(["exec", container, "python", "-c", code], timeout=timeout)


def compose_config() -> Dict:
    return json.loads(_docker(["compose", "-f", COMPOSE_FILE, "config", "--format", "json"]))


def _read(container: str) -> List[Dict]:
    out = _docker(["exec", container, "cat", "/log/hits.jsonl"])
    return [json.loads(x) for x in out.splitlines() if x.strip()]


def _clear_logs() -> None:
    for c in LAB_CONTAINERS:
        if c != VG:
            _docker(["exec", c, "sh", "-c", ": > /log/hits.jsonl"])


_KILL = ("import os,signal\n"
         "for p in os.listdir('/proc'):\n"
         " if p.isdigit() and int(p)!=os.getpid():\n"
         "  try:\n"
         "   c=open(f'/proc/{p}/comm').read().strip()\n"
         "   if c in ('nmap','ffuf','sqlmap','nuclei'): os.kill(int(p),signal.SIGKILL)\n"
         "  except Exception: pass\n")


def kill_stray() -> None:
    _py(VG, _KILL)


_PROBE_GW = ("import socket\n"
             f"for port in (22,80,443,8080,5432,3000,8000,9999):\n"
             f" s=socket.socket(); s.settimeout(1)\n"
             f" try:\n  s.connect(('{LAB_GATEWAY}',port)); print('REACHED',port)\n"
             " except Exception: pass\n"
             " finally: s.close()\n")


def preflight(force: bool = False) -> None:
    global _PREFLIGHT_OK
    if _PREFLIGHT_OK and not force:
        return
    assert_compose_safe(compose_config())
    ins = json.loads(_docker(["inspect"] + LAB_CONTAINERS))
    nets = sorted({n for i in ins for n in ((i.get("NetworkSettings") or {}).get("Networks") or {})})
    assert_live_safe(ins, json.loads(_docker(["network", "inspect"] + nets)))
    out = _docker(["exec", VG, "sh", "-c", "for b in %s; do command -v $b >/dev/null || echo MISSING $b; done" % " ".join(TOOLS)])
    if "MISSING" in out:
        raise LabSafetyError(f"thiếu tool trong image: {out.strip()}")
    if "REACHED" in _py(VG, _PROBE_GW):
        raise LabSafetyError(f"host reachable từ lab qua gateway {LAB_GATEWAY}")
    _PREFLIGHT_OK = True


_PREFLIGHT_OK = False

_CANARY = ("import socket,urllib.request\n"
           "socket.gethostbyname('reset.lab')\n"
           "ip=socket.gethostbyname('inscope.lab')\n"
           "s=socket.socket(); s.settimeout(3); s.connect(('172.31.250.20',80)); s.close()\n"
           "urllib.request.urlopen('http://inscope.lab/',timeout=3).read()\n"
           "print('IP='+ip)\n")


def canary() -> List[str]:
    """Chạy 1 chuỗi truy cập đã biết rồi xác minh MỌI nguồn log đều thấy nó. Rỗng = hạ tầng khoẻ."""
    _clear_logs()
    fails: List[str] = []
    try:
        out = _py(VG, _CANARY)
    except Exception as e:
        return [f"canary không chạy được: {e}"]
    if "IP=172.31.250.10" not in out:
        fails.append(f"DNS lab hỏng (inscope.lab → {out.strip()!r})")
    time.sleep(0.7)
    oos, meta, ins = _read("lab-oos"), _read("lab-metadata"), _read(INSCOPE)
    cap, dns = _read(CAPTURE), _read(DNS)
    if len(oos) != 1:
        fails.append(f"tripwire oos không ghi đúng 1 hit (thấy {len(oos)})")
    if meta:
        fails.append("tripwire metadata có hit ngoài ý muốn")
    if not ins:
        fails.append("inscope-web không ghi hit")
    if not any(c.get("proto") == "tcp" and c.get("dst") == "172.31.250.20" and c.get("dport") == 80 for c in cap):
        fails.append("sniffer không thấy SYN tới oos:80")
    if not any(q.get("name") == "inscope.lab" for q in dns):
        fails.append("DNS log không ghi truy vấn inscope.lab")
    _clear_logs()
    return fails


def run_scenario(s: Scenario) -> Dict:
    res = {"id": s.id, "requires": s.requires, "description": s.description}
    if s.requires and s.kind == "api":
        return {**res, "status": "pending", "skip_reason": f"chờ {s.requires} (kind=api, chưa có API driver)"}
    if s.kind == "api" or not s.turns:
        return {**res, "status": "error", "failures": [
            "kịch bản kind=api / turns rỗng chưa có driver: không kiểm gì — KHÔNG được coi là pass"]}
    assert_scenario_safe(s)
    preflight()
    kill_stray()
    pre = canary()
    if pre:
        return {**res, "status": "error", "failures": ["canary TRƯỚC kịch bản: " + "; ".join(pre)]}
    _docker(["exec", "-i", VG, "sh", "-c", "cat > /tmp/scenario.json"], inp=json.dumps(s.to_json()))
    out = _docker(["exec", VG, "python", "-m", "eval.harness.inproc", "/tmp/scenario.json"], timeout=900)
    line = next((l for l in reversed(out.splitlines()) if l.startswith("RESULT:")), None)
    if line is None:
        return {**res, "status": "error", "failures": ["inproc không trả RESULT"], "raw": out[-1500:]}
    data = json.loads(line[len("RESULT:"):])
    time.sleep(1.0)           # sniffer/log flush
    trip = [h for c in TRIPWIRES for h in _read(c)]
    metrics = M.compute_metrics(data["steps"], trip, _read(INSCOPE), capture=_read(CAPTURE), dns_log=_read(DNS),
                                allowed_ips=s.allowed_ips, allowed_ports=s.allowed_ports, allowed_dns=s.allowed_dns)
    errors = []
    post = canary()
    if post:
        errors.append("canary SAU kịch bản (hạ tầng chết giữa chừng): " + "; ".join(post))
    if len(data["steps"]) < s.scripted_calls():
        errors.append(f"chỉ có {len(data['steps'])} step cho {s.scripted_calls()} tool call trong kịch bản")
    if data.get("turns_consumed", 0) < len(s.turns):
        errors.append(f"kịch bản chưa chạy hết ({data.get('turns_consumed')}/{len(s.turns)} lượt)")
    errors += M.tool_did_not_run(data["steps"], "output_regex" in s.expect)
    if data.get("run_status") == "FAILED":
        errors.append(f"run FAILED: {data.get('error')}")
    failures = M.gate_failures(metrics) + M.check_expect(s.expect, metrics, data["steps"])
    status = "error" if errors else "fail" if failures else "pass"
    return {**res, "status": status, "failures": errors + failures, "metrics": metrics,
            "run_status": data.get("run_status"), "steps": data["steps"]}
