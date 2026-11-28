"""[AI PR-4] SSRF guard cho URL do ADMIN cấu hình (OpenAI-compatible base_url, endpoint Ollama).

Chuỗi kiểm tra: parse chặt → chuẩn hoá host → resolve DNS phía server → deny-list IP → allowlist/cổng →
transport GHIM IP (chống DNS rebinding) → không follow redirect → không đọc proxy env.

  check_url(url, kind)           kiểm tra khi LƯU (và trả URL đã chuẩn hoá); raise UrlRejected
  guarded_async_client(kind)     httpx.AsyncClient cho SDK / probe: kiểm tra LẠI ở MỖI request (call time)
  guarded_client(kind)           bản sync

kind:
  "cloud"  — chỉ https; cổng 443 (+ cổng ADMIN liệt kê); không IP non-global (RFC1918, CGNAT, ULA, loopback…)
             trừ khi host nằm trong allowlist (allowlist KHÔNG mở loopback / link-local / metadata).
  "ollama" — https hoặc http; http chỉ khi MỌI IP resolve là non-global (loopback/LAN). Cổng 11434/80/443
             (+ cổng ADMIN). Loopback & private được phép (đó là chức năng của nó); link-local + metadata
             vẫn bị chặn.

Allowlist host: env `AI_BASE_URL_ALLOWLIST` (CSV, "host", "host:port" hoặc "*.suffix[:port]") + khoá `base_url_allowlist`
(list) trong ai_config + `policy.base_url_allowlist`. Mục không hợp lệ bị bỏ (fail closed). Mục có cổng chỉ mở đúng cặp host:port. Cổng thêm: env `AI_URL_EXTRA_PORTS` (CSV).
Thông điệp lỗi do VulnGuard tự viết (không chứa nội dung phản hồi của provider).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import logging
import socket
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from scanner.pentest.egress_policy import BASE_ALWAYS_DENY

_log = logging.getLogger(__name__)

BAD_BASE_URL = "BAD_BASE_URL"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

_ALWAYS_DENY_NETS = tuple(ipaddress.ip_network(n) for n in BASE_ALWAYS_DENY)
_LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
# Metadata cloud khác ngoài BASE_ALWAYS_DENY (Alibaba 100.100.100.200, Oracle 192.0.0.192) — chặn cả với Ollama
_EXTRA_METADATA = tuple(ipaddress.ip_network(n) for n in ("100.100.100.200/32", "192.0.0.192/32"))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V4_COMPAT = ipaddress.ip_network("::/96")
_NUMERICISH = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+))*$", re.I)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")

_DEFAULT_PORTS = {"cloud": (443,), "ollama": (11434, 80, 443)}


class UrlRejected(ValueError):
    """URL bị từ chối. `reason` là slug ngắn (an toàn để trả UI); message tự viết, không có dữ liệu ngoài."""
    code = BAD_BASE_URL

    def __init__(self, reason: str):
        super().__init__(f"{BAD_BASE_URL}: {reason}")
        self.reason = reason


@dataclass(frozen=True)
class UrlPolicy:
    kind: str = "cloud"                      # 'cloud' | 'ollama'
    allowlist: Tuple[str, ...] = ()
    extra_ports: Tuple[int, ...] = ()
    resolver: Optional[Callable[[str, int], List[str]]] = field(default=None, compare=False)
    configured: Optional[Tuple[str, int]] = None   # (host, port) Ollama đã cấu hình — được dùng cổng 80/443 trên LAN/loopback

    def ports(self) -> Tuple[int, ...]:
        return _DEFAULT_PORTS[self.kind] + tuple(self.extra_ports)

    def _entries(self):
        """(pattern, port|None) của từng mục allowlist ("host", "host:port", "*.suffix[:port]")."""
        for raw in self.allowlist:
            pat = raw.strip().lower().rstrip(".")
            if not pat:
                continue
            host, sep, port = pat.partition(":")
            yield host, (int(port) if sep and port.isdigit() else None)

    @staticmethod
    def _host_matches(pat: str, host: str) -> bool:
        if pat.startswith("*."):
            return host.endswith(pat[1:]) and host != pat[2:]
        return host == pat

    def host_allowlisted(self, host: str, port: Optional[int] = None) -> bool:
        """Mục có cổng chỉ khớp khi đúng cổng; mục không cổng khớp mọi cổng (vẫn phải qua cổng cho phép)."""
        for pat, pport in self._entries():
            if self._host_matches(pat, host) and (pport is None or pport == port):
                return True
        return False

    def port_allowed(self, host: str, port: int) -> bool:
        if port in self.ports():
            return True
        return any(pport == port and self._host_matches(pat, host) for pat, pport in self._entries())


def _checked_entries(entries, source: str) -> List[str]:
    """Chuẩn hoá + bỏ mục không hợp lệ (fail closed). Log chỉ tên nguồn, không log nội dung mục."""
    from api.services.ai_policy import valid_allow_entry
    out: List[str] = []
    bad = 0
    for e in entries:
        e = str(e).strip().lower()
        if not e:
            continue
        if valid_allow_entry(e):
            out.append(e)
        else:
            bad += 1
    if bad:
        _log.warning("url_guard: bỏ %d mục allowlist không hợp lệ từ nguồn %s", bad, source)
    return out


def policy_for(kind: str, resolver=None) -> UrlPolicy:
    """Policy hiệu lực (env + ai_config). Đọc lại ở mỗi lần dùng để thay đổi của ADMIN có hiệu lực ngay."""
    if kind not in _DEFAULT_PORTS:
        raise ValueError("kind phải là 'cloud' hoặc 'ollama'")
    allow = _checked_entries(os.environ.get("AI_BASE_URL_ALLOWLIST", "").split(","), "env")
    ports: List[int] = []
    for p in os.environ.get("AI_URL_EXTRA_PORTS", "").split(","):
        if p.strip().isdigit() and 0 < int(p) < 65536:
            ports.append(int(p))
    try:
        from api.services.ai_config import load_config
        cfg = load_config()
        extra = cfg.get("base_url_allowlist")
        if isinstance(extra, (list, tuple)):
            allow += _checked_entries(extra, "ai_config")
        from api.services.ai_policy import get_policy
        allow += _checked_entries(get_policy(cfg).get("base_url_allowlist") or [], "policy")
    except Exception:
        pass
    configured = None
    if kind == "ollama":
        try:    # URL Ollama hiệu lực (chỉ lấy qua resolver)
            from api.services.llm_resolver import LLMContext, resolve_local
            sp = urlsplit(resolve_local(LLMContext(feature="test")).url)
            if sp.hostname:
                configured = (sp.hostname.lower().rstrip("."), sp.port or (443 if sp.scheme == "https" else 80))
        except Exception:
            pass
    return UrlPolicy(kind, tuple(allow), tuple(ports), resolver, configured)


# ─────────────────────────────────────────────
# DNS (có thể thay trong test)
# ─────────────────────────────────────────────
def _system_resolve(host: str, port: int) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise UrlRejected("không phân giải được host")
    out: List[str] = []
    for fam, _t, _p, _c, sa in infos:
        ip = sa[0].split("%", 1)[0]
        if ip not in out:
            out.append(ip)
    if not out:
        raise UrlRejected("không phân giải được host")
    return out


# ─────────────────────────────────────────────
# Parse + IP rules
# ─────────────────────────────────────────────
def _embedded_v4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64 or ip in _V4_COMPAT:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _loopback_verdict(policy: UrlPolicy) -> Optional[str]:
    return None if policy.kind == "ollama" else "địa chỉ loopback/link-local/metadata bị chặn"


def ip_verdict(ip_text: str, policy: UrlPolicy, host_allowlisted: bool = False) -> Optional[str]:
    """None = được phép; ngược lại slug lý do."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "IP không hợp lệ"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.sixtofour is not None or ip.teredo is not None:
            return "IPv6 chuyển tiếp (6to4/Teredo) bị chặn"
        v4 = _embedded_v4(ip)
        if v4 is not None:
            return ip_verdict(str(v4), policy, host_allowlisted) if ip != ipaddress.IPv6Address("::1") else _loopback_verdict(policy)
    if any(ip in lb for lb in _LOOPBACK_NETS):
        return _loopback_verdict(policy)
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved or (isinstance(ip, ipaddress.IPv4Address) and str(ip) == "255.255.255.255"):
        return "địa chỉ đặc biệt bị chặn"
    if any(ip in n for n in _EXTRA_METADATA):
        return "địa chỉ metadata bị chặn"
    for net in _ALWAYS_DENY_NETS:
        if ip.version != net.version or ip not in net:
            continue
        if policy.kind == "ollama" and any(ip in lb for lb in _LOOPBACK_NETS):
            continue            # Ollama chạy local: loopback hợp lệ; link-local + metadata vẫn chặn
        return "địa chỉ loopback/link-local/metadata bị chặn"
    if ip.is_link_local:
        return "địa chỉ link-local bị chặn"
    if not ip.is_global and policy.kind == "cloud" and not host_allowlisted:
        return "địa chỉ nội bộ chỉ được phép khi host nằm trong allowlist"
    return None


def parse_url(url: str, policy: UrlPolicy) -> Tuple[str, str, int, str]:
    """Trả (scheme, host_đã_chuẩn_hoá, port, path). Không mạng."""
    if not isinstance(url, str) or not url.strip():
        raise UrlRejected("URL rỗng")
    url = url.strip()
    if len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise UrlRejected("URL chứa ký tự không hợp lệ")
    try:
        sp = urlsplit(url)
        port = sp.port
    except ValueError:
        raise UrlRejected("URL không hợp lệ")
    scheme = sp.scheme.lower()
    if scheme not in ("https", "http"):
        raise UrlRejected("chỉ chấp nhận https")
    if scheme == "http" and policy.kind != "ollama":
        raise UrlRejected("chỉ chấp nhận https")
    if "@" in sp.netloc:
        raise UrlRejected("không cho phép userinfo trong URL")
    if sp.fragment or sp.query or "#" in url or "?" in url:
        raise UrlRejected("không cho phép query/fragment")
    raw_host = sp.hostname
    if not raw_host:
        raise UrlRejected("thiếu host")
    host = _normalise_host(raw_host)
    port = port or (443 if scheme == "https" else 80)
    if not policy.port_allowed(host, port):
        raise UrlRejected(f"cổng {port} không nằm trong danh sách cho phép")
    path = sp.path.rstrip("/")
    if ".." in path.split("/"):
        raise UrlRejected("path không hợp lệ")
    return scheme, host, port, path


def _normalise_host(raw: str) -> str:
    if "%" in raw:
        raise UrlRejected("host không hợp lệ")
    if ":" in raw:                                   # IPv6 literal
        try:
            return str(ipaddress.IPv6Address(raw))
        except ValueError:
            raise UrlRejected("host không hợp lệ")
    try:
        host = raw.encode("idna").decode("ascii").lower().rstrip(".")   # NFKC/nameprep: fullwidth → ASCII
    except UnicodeError:
        raise UrlRejected("host không hợp lệ")
    if not host:
        raise UrlRejected("host không hợp lệ")
    if _NUMERICISH.match(host):                      # IP dạng thập phân/hex/bát phân/rút gọn: 2130706433, 0x7f.1, 0177.0.0.1
        try:
            return str(ipaddress.IPv4Address(host))  # chỉ dotted-quad chuẩn
        except ValueError:
            raise UrlRejected("IP viết không chuẩn (thập phân/hex/bát phân) bị chặn")
    if not _HOSTNAME.match(host):
        raise UrlRejected("host không hợp lệ")
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_host(host: str, scheme: str, port: int, policy: UrlPolicy) -> List[str]:
    """Resolve + kiểm MỌI IP trả về. Trả danh sách IP đã được duyệt (để ghim). Raise UrlRejected."""
    if _is_ip(host):
        ips = [host]
    else:
        ips = (policy.resolver or _system_resolve)(host, port)
    allow = policy.host_allowlisted(host, port)
    for ip in ips:
        why = ip_verdict(ip, policy, allow)
        if why:
            raise UrlRejected(why)
    if (policy.kind == "ollama" and port in (80, 443) and port not in policy.extra_ports
            and policy.configured != (host, port)
            and any(not ipaddress.ip_address(i).is_global for i in ips)):
        # LAN/loopback trên 80/443 chỉ khi đó đúng là host:port Ollama đã cấu hình (hạn chế dò host nội bộ)
        raise UrlRejected("cổng 80/443 trên địa chỉ nội bộ chỉ được dùng cho host:port Ollama đã cấu hình")
    if scheme == "http":   # http (chỉ Ollama) khi mọi IP là non-global
        if any(ipaddress.ip_address(i).is_global for i in ips):
            raise UrlRejected("http chỉ được phép tới địa chỉ local/LAN; địa chỉ public cần https")
    return ips


def check_url(url: str, kind: str = "cloud", *, policy: Optional[UrlPolicy] = None,
              explicit_ollama: bool = False) -> str:
    """Kiểm tra khi LƯU. Trả URL chuẩn hoá (host đã chuẩn hoá, bỏ '/' cuối). Raise UrlRejected.
    explicit_ollama=True: ADMIN đang đặt chính URL này làm Ollama (cho phép 80/443 trên LAN)."""
    pol = policy or policy_for(kind)
    scheme, host, port, path = parse_url(url, pol)
    if explicit_ollama and kind == "ollama":
        pol = replace(pol, configured=(host, port))
    check_host(host, scheme, port, pol)
    netloc = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    if port != default:
        netloc += f":{port}"
    return f"{scheme}://{netloc}{path}"


# ─────────────────────────────────────────────
# Transport ghim IP (call time)
# ─────────────────────────────────────────────
def _pin(request: httpx.Request, policy: UrlPolicy) -> None:
    url = request.url
    host = url.host
    port = url.port or (443 if url.scheme == "https" else 80)
    if url.scheme not in ("http", "https"):
        raise UrlRejected("scheme không hợp lệ")
    if url.scheme == "http" and policy.kind != "ollama":
        raise UrlRejected("chỉ chấp nhận https")
    host = _normalise_host(host)
    if not policy.port_allowed(host, port):
        raise UrlRejected(f"cổng {port} không nằm trong danh sách cho phép")
    ips = check_host(host, url.scheme, port, policy)
    ip = ips[0]
    if host != ip:
        # Kết nối tới đúng IP đã kiểm; header Host giữ nguyên; SNI/verify cert theo hostname gốc
        request.url = url.copy_with(host=ip)
        request.extensions = {**request.extensions, "sni_hostname": host}


def _make_transports(lib):
    """Dựng transport + exception cho một thư viện httpx (httpx hoặc httpx2 — SDK anthropic 2.x dùng httpx2)."""
    class _Rejected(GuardRejected, lib.TransportError):
        pass

    class Async(lib.AsyncBaseTransport):
        def __init__(self, policy: UrlPolicy, inner=None):
            self._policy = policy
            self._inner = inner or lib.AsyncHTTPTransport(retries=0)

        async def handle_async_request(self, request):
            try:
                await asyncio.to_thread(_pin, request, self._policy)
            except UrlRejected as e:
                raise _Rejected(str(e), request=request) from None
            return await self._inner.handle_async_request(request)

        async def aclose(self) -> None:
            await self._inner.aclose()

    class Sync(lib.BaseTransport):
        def __init__(self, policy: UrlPolicy, inner=None):
            self._policy = policy
            self._inner = inner or lib.HTTPTransport(retries=0)

        def handle_request(self, request):
            try:
                _pin(request, self._policy)
            except UrlRejected as e:
                raise _Rejected(str(e), request=request) from None
            return self._inner.handle_request(request)

        def close(self) -> None:
            self._inner.close()
    return Async, Sync


class GuardRejected(httpx.TransportError):
    """Request bị guard chặn lúc gọi (rebinding, IP bị cấm…). Là TransportError nên SDK/caller coi như lỗi mạng."""


GuardedAsyncTransport, GuardedTransport = _make_transports(httpx)
_LIBS = {"httpx": httpx}


def _lib(name: str):
    if name not in _LIBS:
        import httpx2
        _LIBS[name] = httpx2
    return _LIBS[name]


_T2: dict = {}


def guarded_async_client(kind: str = "cloud", *, timeout=10.0, policy: Optional[UrlPolicy] = None,
                         inner=None, lib: str = "httpx"):
    """lib='httpx2' cho SDK anthropic (>=2.x). Luôn: không redirect, không proxy env, kiểm IP ở mỗi request."""
    pol = policy or policy_for(kind)
    m = _lib(lib)
    if lib == "httpx":
        t = GuardedAsyncTransport(pol, inner)
    else:
        if lib not in _T2:
            _T2[lib] = _make_transports(m)
        t = _T2[lib][0](pol, inner)
    return m.AsyncClient(transport=t, follow_redirects=False, trust_env=False, timeout=timeout)


def guarded_client(kind: str = "cloud", *, timeout: float = 10.0, policy: Optional[UrlPolicy] = None,
                   inner: Optional[httpx.BaseTransport] = None) -> httpx.Client:
    pol = policy or policy_for(kind)
    return httpx.Client(transport=GuardedTransport(pol, inner), follow_redirects=False,
                        trust_env=False, timeout=timeout)


def plain_async_client(lib: str = "httpx", *, timeout=10.0):
    """Client cho host cố định của provider: không proxy env, không redirect (không guard IP)."""
    return _lib(lib).AsyncClient(trust_env=False, follow_redirects=False, timeout=timeout)


async def read_capped(resp: httpx.Response, cap: int = MAX_RESPONSE_BYTES) -> bytes:
    """Đọc body tối đa `cap` byte (resp phải mở bằng stream)."""
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        buf += chunk
        if len(buf) > cap:
            raise UrlRejected("phản hồi quá lớn")
    return bytes(buf)
