"""Cô lập compose của benchmark bên thứ ba (XBOW, AutoPenBench…) vào lab. Hàm THUẦN, test offline.

Hợp đồng: `assert_bench_compose_safe(cfg, allowed_ips, phase="pre")` chạy trên compose GỐC (từ chối FAIL-CLOSED mọi khoá có thể
thoát khỏi lab), `transform_compose` viết lại (mọi service chỉ nối lab_net(external)+bench_internal(internal), bỏ `ports`),
rồi `assert_bench_compose_safe(out, allowed_ips, phase="post")` kiểm lại KẾT QUẢ. Không nới danh sách từ chối để một challenge chạy
được — bỏ challenge đó khỏi selection.

`ports` ở phase "pre" được chấp nhận vì transform xoá hết (không bao giờ publish ra host) và đó là cách upstream đánh dấu service
lộ cổng; ở phase "post" `ports` bị cấm tuyệt đối."""
import copy
import ipaddress
import logging
from typing import Dict, Iterable, List, Optional

LAB_NETWORK = "vglab_lab_net"          # project `vglab` + network `lab_net` của docker-compose.lab.yml
LAB_NET = ipaddress.ip_network("172.31.250.0/24")
BENCH_NET = "bench_internal"
log = logging.getLogger(__name__)


class UnsafeCompose(RuntimeError):
    """Compose có khoá/giá trị có thể thoát khỏi cô lập của lab."""


# Khoá cấp service bị từ chối khi có BẤT KỲ giá trị truthy nào.
_FORBIDDEN_ANY = ("network_mode", "privileged", "cap_add", "devices", "pid", "ipc", "uts", "userns_mode", "extra_hosts", "dns",
                  "dns_search", "dns_opt", "sysctls", "cgroup", "cgroup_parent", "volumes_from", "runtime", "secrets", "configs",
                  "external_links", "links", "device_cgroup_rules", "group_add")


def _host_source(v) -> bool:
    """True nếu mục volumes là bind mount từ đường dẫn host (tuyệt đối, ~, .., biến, './x:/y' hoặc long-syntax type=bind)."""
    if isinstance(v, dict):
        return v.get("type") == "bind" or _host_source(str(v.get("source") or ""))
    src = str(v).split(":", 1)[0]
    return src.startswith(("/", "~", "..", "$")) or (":" in str(v) and src.startswith("."))


def _as_dict(x) -> Dict:
    return x if isinstance(x, dict) else {}


def assert_bench_compose_safe(cfg: Dict, allowed_ips: Iterable[str], phase: str = "pre") -> None:
    """Từ chối (fail closed) với UnsafeCompose. phase="pre": compose gốc; phase="post": compose đã `transform_compose`."""
    if phase not in ("pre", "post"):
        raise ValueError(f"phase không hợp lệ: {phase}")
    allowed = {str(i) for i in allowed_ips}
    for ip in allowed:
        a = ipaddress.ip_address(ip)
        if a not in LAB_NET or str(a) in (str(LAB_NET.network_address), "172.31.250.1", str(LAB_NET.broadcast_address)):
            raise UnsafeCompose(f"ip ngoài lab: {ip}")
    services = cfg.get("services")
    if not isinstance(services, dict) or not services:
        raise UnsafeCompose("compose không có services")
    for name, svc in services.items():
        svc = _as_dict(svc)
        for bad in _FORBIDDEN_ANY:
            if svc.get(bad):
                raise UnsafeCompose(f"service {name}: `{bad}` bị cấm")
        if phase == "post" and svc.get("ports"):
            raise UnsafeCompose(f"service {name}: `ports` bị cấm (không publish ra host)")
        if any("unconfined" in str(o) for o in (svc.get("security_opt") or [])):
            raise UnsafeCompose(f"service {name}: security_opt unconfined bị cấm")
        for v in svc.get("volumes") or []:
            if "docker.sock" in str(v):
                raise UnsafeCompose(f"service {name}: mount docker.sock bị cấm")
            if _host_source(v):
                raise UnsafeCompose(f"service {name}: bind mount từ host bị cấm: {v}")
        b = svc.get("build")
        if isinstance(b, dict):
            if str(b.get("network") or "").lower() == "host":
                raise UnsafeCompose(f"service {name}: build.network=host bị cấm")
            for bad in ("extra_hosts", "privileged", "cap_add"):
                if b.get(bad):
                    raise UnsafeCompose(f"service {name}: build.{bad} bị cấm")
        if svc.get("image") and "@sha256:" not in str(svc["image"]) and not b:
            log.warning("service %s: image %s không ghim digest (chỉ cho phép khi build cục bộ)", name, svc["image"])
        nets = svc.get("networks")
        if phase == "post":
            names = set(nets) if isinstance(nets, (dict, list)) else set()
            if not names or not names <= {"lab_net", BENCH_NET}:
                raise UnsafeCompose(f"service {name}: network lạ {sorted(names)}")
            for n, spec in _as_dict(nets).items():
                ip = _as_dict(spec).get("ipv4_address")
                if ip and str(ip) not in allowed:
                    raise UnsafeCompose(f"service {name}: ipv4_address {ip} không nằm trong allowed_ips")
                if n == BENCH_NET and ip:
                    raise UnsafeCompose(f"service {name}: bench_internal không được có IP cố định")
    top = _as_dict(cfg.get("networks"))
    if phase == "pre":
        for n, spec in top.items():
            spec = _as_dict(spec)
            if spec.get("external") not in (None, False, "false"):
                raise UnsafeCompose(f"network {n}: external bị cấm")
            if str(spec.get("driver") or "bridge") not in ("bridge",):
                raise UnsafeCompose(f"network {n}: driver {spec.get('driver')} bị cấm")
    else:
        if set(top) != {"lab_net", BENCH_NET}:
            raise UnsafeCompose(f"networks phải là lab_net(external) + bench_internal(internal), có {sorted(top)}")
        lab, bench = _as_dict(top["lab_net"]), _as_dict(top[BENCH_NET])
        if lab.get("external") is not True or lab.get("name") != LAB_NETWORK:
            raise UnsafeCompose("lab_net phải là external và trỏ tới mạng của lab")
        if bench.get("internal") is not True:
            raise UnsafeCompose("bench_internal phải `internal: true`")


def _container_port(svc: Dict) -> Optional[int]:
    for key in ("ports", "expose"):
        for p in svc.get(key) or []:
            s = str(p).split("/")[0]
            return int(s.rsplit(":", 1)[-1])
    return None


def _strip_health(svc: Dict) -> None:
    """Healthcheck của benchmark hay dùng công cụ image không có (XBEN-007: `curl`) ⇒ `up --wait` lỗi ⇒ cả run chết.
    Bỏ healthcheck; harness thăm dò sự sẵn sàng bằng HTTP từ vg-under-test."""
    svc.pop("healthcheck", None)
    dep = svc.get("depends_on")
    if isinstance(dep, dict):
        svc["depends_on"] = {k: {**(v or {}), "condition": "service_started"} for k, v in dep.items()}


def transform_compose(cfg: Dict, ip: str, lab_network: str = LAB_NETWORK, entry: Optional[str] = None) -> Dict:
    """THUẦN (không sửa `cfg`). Bỏ mọi `ports` (không publish ra host), đặt service lộ cổng lên lab_net (IP cố định) + mạng nội bộ
    của benchmark (`internal: true`); service còn lại (DB…) CHỈ ở mạng nội bộ. `entry` = tên service lộ cổng (mặc định: service duy nhất có
    `ports`). Cổng web ở `x-vg-entry-port`."""
    names = [entry] if entry else [n for n, s in cfg["services"].items() if s.get("ports")]
    if len(names) != 1 or names[0] not in cfg["services"]:
        raise ValueError(f"cần đúng 1 service lộ cổng, có {names}")
    port = _container_port(cfg["services"][names[0]])
    if port is None:
        raise ValueError(f"service {names[0]} không khai báo cổng (ports/expose)")
    out = {k: v for k, v in cfg.items() if k not in ("networks", "services", "name")}
    out["networks"] = {"lab_net": {"external": True, "name": lab_network}, BENCH_NET: {"internal": True}}
    out["services"] = {}
    for name, svc in cfg["services"].items():
        s = {k: v for k, v in svc.items() if k not in ("ports", "networks", "container_name", "network_mode", "privileged")}
        _strip_health(s)
        if name == names[0]:
            s["expose"] = [str(port)]
            s["networks"] = {"lab_net": {"ipv4_address": ip}, BENCH_NET: {}}
            out["x-vg-entry-port"] = port
        else:
            s["networks"] = {BENCH_NET: {}}
        out["services"][name] = s
    return copy.deepcopy(out)


def rewrite_and_check(cfg: Dict, ip: str, entry: Optional[str] = None) -> Dict:
    """pre-check → transform → post-check. Trả compose đã cô lập (kèm `x-vg-entry-port`)."""
    assert_bench_compose_safe(cfg, [ip], "pre")
    out = transform_compose(cfg, ip, entry=entry)
    assert_bench_compose_safe({k: v for k, v in out.items() if k != "x-vg-entry-port"}, [ip], "post")
    return out
