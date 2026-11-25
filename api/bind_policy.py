"""Chính sách bind mạng (truy cập LAN) — dùng chung cho startup check.

`VULNGUARD_BIND` là biến chuẩn (Docker compose + native). `VULNGUARD_HOST` là alias deprecated.
Mặc định loopback. Mở ra ngoài (non-loopback) bị từ chối khi `AUTH_ENABLED=false`.
"""
import logging
import os
from typing import Mapping, Optional, Tuple

log = logging.getLogger(__name__)

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def resolve_bind(env: Optional[Mapping[str, str]] = None) -> Tuple[str, bool]:
    """→ (bind, dùng_alias_deprecated). Ưu tiên VULNGUARD_BIND, rồi VULNGUARD_HOST, rồi 127.0.0.1."""
    e = os.environ if env is None else env
    b = (e.get("VULNGUARD_BIND") or "").strip()
    if b:
        return b, False
    h = (e.get("VULNGUARD_HOST") or "").strip()
    if h:
        return h, True
    return "127.0.0.1", False


def is_loopback(bind: str) -> bool:
    return bind.strip().lower() in LOOPBACK


def check_startup(bind: str, auth_enabled: bool, allowed_hosts: str, cookie_secure: bool) -> None:
    """Từ chối khởi động nếu auth tắt mà bind non-loopback; cảnh báo các cấu hình LAN kém an toàn."""
    if is_loopback(bind):
        return
    if not auth_enabled:
        raise RuntimeError(
            f"AUTH_ENABLED=false không được phép khi VULNGUARD_BIND={bind} (mở ra mạng không xác thực). "
            "Bật AUTH_ENABLED=true hoặc dùng VULNGUARD_BIND=127.0.0.1.")
    log.warning("[bind] Đang nghe/publish trên %s (truy cập từ máy khác trong mạng). "
                "Đảm bảo đã có tài khoản ADMIN/setup token và firewall.", bind)
    if not (allowed_hosts or "").strip():
        log.warning("[bind] ALLOWED_HOSTS trống: chấp nhận mọi Host header. "
                    "Nên đặt ALLOWED_HOSTS=<ip/hostname LAN>, ví dụ 192.168.1.63,vulnguard.lan")
    if not cookie_secure:
        log.warning("[bind] Session cookie đi qua HTTP thuần trong LAN. Khuyến nghị TLS qua reverse proxy "
                    "(Caddy/nginx) + COOKIE_SECURE=true (xem wiki 'Truy cập từ máy khác trong LAN').")
