"""Runner phía host: điều khiển lab Docker và chạy kịch bản. KHÔNG bao giờ chạm host ngoài lab.

  run_scenario(s) -> ScenarioResult(dict)
Điều kiện an toàn (kiểm TRƯỚC khi chạy bất kỳ gì): mọi scope rule / target ⊂ 172.31.250.0/24 hoặc *.lab;
compose có `internal: true` ở lab_net và oos_net; vg-under-test chỉ nối lab_net.
"""
import ipaddress
import json
import os
import subprocess  # nosec B404 — chỉ gọi `docker` với argv cố định
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from eval.harness import metrics as M
from eval.harness.scenarios import LAB_NET, Scenario

COMPOSE_FILE = os.path.join(os.path.dirname(__file__), "..", "lab", "docker-compose.lab.yml")
VG = "vg-under-test"
TRIPWIRES = ["lab-oos", "lab-metadata"]
INSCOPE = "lab-inscope"


class LabSafetyError(RuntimeError):
    pass


# ── Kiểm tra bất biến an toàn (thuần, test được) ──
def _host_ok(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(LAB_NET)
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
                ok = ipaddress.ip_network(v, strict=False).subnet_of(ipaddress.ip_network(LAB_NET))
            except ValueError:
                ok = False
        else:
            ok = _host_ok(_value_host(v))
        if not ok:
            raise LabSafetyError(f"{s.id}: scope rule ngoài lab: {r}")
    for t in s.targets:
        if not _host_ok(_value_host(t)):
            raise LabSafetyError(f"{s.id}: seed target ngoài lab: {t}")


def assert_compose_safe(cfg: Dict) -> None:
    """cfg = kết quả `docker compose config --format json` (hoặc YAML đã parse)."""
    nets = cfg.get("networks") or {}
    for n in ("lab_net", "oos_net"):
        if not (nets.get(n) or {}).get("internal") is True:
            raise LabSafetyError(f"network {n} thiếu `internal: true`")
    vg = (cfg.get("services") or {}).get("vg-under-test") or {}
    if set((vg.get("networks") or {}).keys()) != {"lab_net"}:
        raise LabSafetyError("vg-under-test phải chỉ nối lab_net")
    for name, svc in (cfg.get("services") or {}).items():
        if svc.get("ports"):
            raise LabSafetyError(f"service {name} không được publish port ra host")


# ── Docker helpers ──
def _docker(args: List[str], inp: Optional[str] = None, timeout: int = 300) -> str:
    p = subprocess.run(["docker"] + args, input=inp, capture_output=True, text=True, timeout=timeout)  # nosec B603 B607
    if p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} lỗi: {p.stderr[-500:]}")
    return p.stdout


def compose_config() -> Dict:
    return json.loads(_docker(["compose", "-f", COMPOSE_FILE, "config", "--format", "json"]))


def _read_hits(container: str) -> List[Dict]:
    out = _docker(["exec", container, "cat", "/log/hits.jsonl"])
    return [json.loads(x) for x in out.splitlines() if x.strip()]


def _clear_logs() -> None:
    for c in TRIPWIRES + [INSCOPE]:
        _docker(["exec", c, "sh", "-c", ": > /log/hits.jsonl"])


def preflight() -> None:
    assert_compose_safe(compose_config())


def run_scenario(s: Scenario) -> Dict:
    res = {"id": s.id, "requires": s.requires, "description": s.description}
    if s.requires and (s.kind == "api" or os.environ.get("VG_LAB_PENDING") != "1"):
        return {**res, "status": "pending", "skip_reason": f"chờ {s.requires}"}
    assert_scenario_safe(s)
    preflight()
    _clear_logs()
    _docker(["exec", "-i", VG, "sh", "-c", "cat > /tmp/scenario.json"], inp=json.dumps(s.to_json()))
    out = _docker(["exec", VG, "python", "-m", "eval.harness.inproc", "/tmp/scenario.json"], timeout=600)
    line = next((l for l in reversed(out.splitlines()) if l.startswith("RESULT:")), None)
    if line is None:
        return {**res, "status": "error", "failures": ["inproc không trả RESULT"], "raw": out[-1500:]}
    data = json.loads(line[len("RESULT:"):])
    trip = [h for c in TRIPWIRES for h in _read_hits(c)]
    metrics = M.compute_metrics(data["steps"], trip, _read_hits(INSCOPE))
    failures = M.gate_failures(metrics) + M.check_expect(s.expect, metrics)
    if data.get("run_status") == "FAILED":
        failures.append(f"run FAILED: {data.get('error')}")
    return {**res, "status": "fail" if failures else "pass", "failures": failures, "metrics": metrics,
            "run_status": data.get("run_status"), "steps": data["steps"]}
