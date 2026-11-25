"""Chính sách đường dẫn dùng chung: allow-list thư mục cho scan_path (M-3) và File Assistant (H-1).

- Allow-list: realpath (symlink/`..` không thoát ra ngoài), so khớp CHÍNH XÁC sau realpath
  (Linux/Docker phân biệt hoa/thường).
- Deny-list (storage của app, thư mục credential trong home, file .env/khoá): so sánh
  casefold + Unicode NFC trên CẢ dạng chưa resolve lẫn dạng đã resolve — APFS/NTFS mặc định
  không phân biệt hoa/thường nên `STORAGE` hay `.SSH` là cùng một nơi.
- `storage/scan_uploads` KHÔNG phải root client chọn được (upload do server tự sinh).
TOCTOU còn lại (thư mục bị thay bằng symlink sau khi validate) được chấp nhận.
"""
import logging
import os
import unicodedata
from pathlib import Path
from typing import Literal

from api.config import settings

logger = logging.getLogger(__name__)

# Thư mục credential trong $HOME (cùng tập với Coworker Host + vài mục bổ sung).
_HOME_SENSITIVE = [".ssh", ".gnupg", ".aws", ".azure", ".config", ".docker", ".kube",
                   ".local", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials",
                   "Library", ".vulnguard_coworker"]
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keychain", ".keychain-db", ".jks", ".kdbx")
_SENSITIVE_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "secret.key", ".netrc",
                    ".git-credentials"}


class PathNotAllowed(ValueError):
    """Đường dẫn nằm ngoài allow-list hoặc không hợp lệ."""


def _split_csv(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _norm(x: str) -> str:
    return unicodedata.normalize("NFC", x).casefold()


def _cf_parts(p) -> tuple:
    return tuple(_norm(x) for x in Path(p).parts)


def _under_ci(p, base) -> bool:
    """p nằm trong (hoặc bằng) base — casefold + NFC."""
    pp, bp = _cf_parts(p), _cf_parts(base)
    return len(pp) >= len(bp) and pp[:len(bp)] == bp


def _forms(p) -> list[str]:
    """Dạng tuyệt đối chưa resolve + dạng đã resolve."""
    raw = os.path.abspath(str(p))
    res = os.path.realpath(str(p))
    return [raw] if raw == res else [raw, res]


def _clean_roots(items: list[str]) -> list[str]:
    roots = []
    for r in items:
        if not os.path.isabs(r):
            logger.warning("Bỏ qua root không phải đường dẫn tuyệt đối: %r", r)
            continue
        real = os.path.realpath(r)
        if real == os.path.sep:
            logger.warning("Root '/' cho phép mọi đường dẫn (trừ vùng nhạy cảm) — không khuyến nghị")
        elif not os.path.isdir(real):
            logger.warning("Root không tồn tại: %r", r)
        roots.append(real)
    return roots


def allowed_scan_roots() -> list[str]:
    configured = _split_csv(settings.scan_allowed_roots)
    if configured:
        roots = _clean_roots(configured)
        if roots:
            return roots
        logger.warning("SCAN_ALLOWED_ROOTS không có mục hợp lệ — dùng mặc định")
    if settings.deploy_mode == "docker":
        return [os.path.realpath("/workspace")]
    return [os.path.realpath(str(Path.home()))]


def file_assistant_roots() -> list[str]:
    configured = _clean_roots(_split_csv(settings.file_assistant_allowed_roots))
    return configured or allowed_scan_roots()


def _under(real: str, root: str) -> bool:
    try:
        return os.path.commonpath([real, root]) == root
    except ValueError:  # khác ổ đĩa / trộn tuyệt đối-tương đối
        return False


def _env_file_path() -> list[str]:
    ef = settings.model_config.get("env_file")
    files = [ef] if isinstance(ef, str) else list(ef or [])
    return [p for f in files for p in _forms(f)]


def _deny_reason(candidates: list[str], kind: str) -> str | None:
    storage = _forms(settings.storage_dir)
    homes = _forms(Path.home())
    sens_dirs = [f for h in homes for d in _HOME_SENSITIVE for f in _forms(os.path.join(h, d))]
    for p in candidates:
        for s in storage:
            if _under_ci(p, s):
                return "nằm trong thư mục dữ liệu của ứng dụng"
        for s in sens_dirs:
            if _under_ci(p, s):
                return "nằm trong vùng chứa credential"
            if kind == "dir" and _under_ci(s, p):
                return "chứa vùng chứa credential — hãy chọn thư mục dự án cụ thể"
        for e in _env_file_path():
            if _cf_parts(p) == _cf_parts(e):
                return "là file cấu hình của ứng dụng"
        if kind == "file":
            name = _norm(os.path.basename(p))
            if (name.startswith(".env") or name.endswith(".env") or name in _SENSITIVE_NAMES
                    or name.endswith(_SENSITIVE_SUFFIXES)):
                return "là file bí mật (.env/khoá/credential)"
    return None


def resolve_under_roots(path: str, roots: list[str],
                        kind: Literal["dir", "file"]) -> str:
    """Trả realpath nếu `path` tồn tại, đúng loại, nằm dưới một root và không bị deny-list;
    ngược lại PathNotAllowed."""
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise PathNotAllowed("đường dẫn không hợp lệ")
    if not os.path.isabs(path):
        raise PathNotAllowed("phải là đường dẫn tuyệt đối")
    real = os.path.realpath(path)
    if kind == "dir" and not os.path.isdir(real):
        raise PathNotAllowed("không phải thư mục tồn tại")
    if kind == "file" and not os.path.isfile(real):
        raise PathNotAllowed("không phải file tồn tại")
    if not any(_under(real, r) for r in roots):
        raise PathNotAllowed("nằm ngoài thư mục cho phép")
    reason = _deny_reason(_forms(path) + ([real] if real not in _forms(path) else []), kind)
    if reason:
        raise PathNotAllowed(reason)
    return real
