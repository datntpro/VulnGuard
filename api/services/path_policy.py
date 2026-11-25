"""Chính sách đường dẫn dùng chung: allow-list thư mục cho scan_path (M-3) và File Assistant (H-1).

Mọi đường dẫn do client gửi phải nằm dưới một "root" cho phép (sau realpath, nên symlink
và `..` không thoát ra ngoài). Storage của app (DB, secret.key…) luôn bị chặn, trừ
`scan_uploads`. TOCTOU còn lại (thư mục bị thay bằng symlink sau khi validate) được chấp nhận.
"""
import os
from pathlib import Path
from typing import Literal

from api.config import settings


class PathNotAllowed(ValueError):
    """Đường dẫn nằm ngoài allow-list hoặc không hợp lệ."""


def _split_csv(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _uploads_root() -> str:
    return os.path.realpath(os.path.join(settings.storage_dir, "scan_uploads"))


def allowed_scan_roots() -> list[str]:
    configured = _split_csv(settings.scan_allowed_roots)
    if configured:
        roots = [os.path.realpath(r) for r in configured]
    elif settings.deploy_mode == "docker":
        roots = [os.path.realpath("/workspace")]
    else:
        roots = [os.path.realpath(str(Path.home()))]
    roots.append(_uploads_root())
    return roots


def file_assistant_roots() -> list[str]:
    configured = _split_csv(settings.file_assistant_allowed_roots)
    if configured:
        return [os.path.realpath(r) for r in configured]
    return allowed_scan_roots()


def _under(real: str, root: str) -> bool:
    try:
        return os.path.commonpath([real, root]) == root
    except ValueError:  # khác ổ đĩa / trộn tuyệt đối-tương đối
        return False


def resolve_under_roots(path: str, roots: list[str],
                        kind: Literal["dir", "file"]) -> str:
    """Trả realpath nếu `path` tồn tại, đúng loại và nằm dưới một root; ngược lại PathNotAllowed."""
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise PathNotAllowed("đường dẫn không hợp lệ")
    real = os.path.realpath(path)
    if kind == "dir" and not os.path.isdir(real):
        raise PathNotAllowed("không phải thư mục tồn tại")
    if kind == "file" and not os.path.isfile(real):
        raise PathNotAllowed("không phải file tồn tại")
    if not any(_under(real, r) for r in roots):
        raise PathNotAllowed("nằm ngoài thư mục cho phép")
    # Storage của app (DB, secret.key, …) luôn bị chặn, trừ scan_uploads.
    storage = os.path.realpath(settings.storage_dir)
    uploads = _uploads_root()
    if _under(real, storage) and not _under(real, uploads):
        raise PathNotAllowed("nằm trong thư mục dữ liệu của ứng dụng")
    return real
