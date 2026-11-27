"""Build the private Typst project root.

Typst follows symlinks inside its root (probe F3), so the root is assembled by *copying*
regular files from our own package into a fresh 0700 temp dir, and then re-verified.
It never lives under the repo or ``storage/``.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Iterator, Mapping, NamedTuple

from .errors import UnsafeRoot

PKG_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PKG_DIR / "templates"
LEGACY_FONTS_DIR = PKG_DIR.parent / "assets" / "fonts"  # DejaVu; PR-2 moves fonts into templates/fonts
FONT_SUFFIXES = {".ttf", ".otf", ".ttc", ".woff2"}
ALLOWED_SUFFIXES = {".typ", ".png"} | FONT_SUFFIXES
MAX_ROOT_BYTES = 64 * 1024 * 1024


class Workspace(NamedTuple):
    base: Path      # parent temp dir (0700)
    root: Path      # typst project root: only templates/fonts/assets
    home: Path      # worker HOME (empty)
    packages: Path  # empty package_path
    pkg_cache: Path # empty package_cache_path


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def verify_root(root: Path, *, allowed_suffixes=ALLOWED_SUFFIXES) -> int:
    """Raise UnsafeRoot unless ``root`` holds only plain dirs + allow-listed regular files
    (no symlinks, no hardlinks, no specials). Returns total bytes."""
    root = Path(root)
    try:
        st = os.lstat(root)
    except OSError as e:
        raise UnsafeRoot("root missing") from e
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeRoot("root is not a directory")
    total = 0
    for dp, dns, fns in os.walk(root, followlinks=False):
        for name in dns + fns:
            p = Path(dp, name)
            m = os.lstat(p)
            if stat.S_ISLNK(m.st_mode):
                raise UnsafeRoot(f"symlink in root: {p.relative_to(root)}")
            if stat.S_ISDIR(m.st_mode):
                continue
            if not stat.S_ISREG(m.st_mode):
                raise UnsafeRoot(f"special file in root: {p.relative_to(root)}")
            if m.st_nlink > 1:
                raise UnsafeRoot(f"hardlink in root: {p.relative_to(root)}")
            if p.suffix.lower() not in allowed_suffixes:
                raise UnsafeRoot(f"unexpected file type in root: {p.relative_to(root)}")
            total += m.st_size
    if total > MAX_ROOT_BYTES:
        raise UnsafeRoot("root too large")
    return total


def _copy_tree_plain(src: Path, dst: Path, *, allowed_suffixes, skip_others: bool = False) -> None:
    """Copy regular files only; refuse symlinks in the *source* too. With ``skip_others``
    non-whitelisted regular files (e.g. OFL.txt next to fonts) are silently left behind."""
    if not src.exists():
        return
    if src.is_symlink():
        raise UnsafeRoot(f"symlinked source: {src.name}")
    for dp, dns, fns in os.walk(src, followlinks=False):
        rel = Path(dp).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for name in dns:
            if os.path.islink(Path(dp, name)):
                raise UnsafeRoot(f"symlinked source dir: {name}")
        for name in fns:
            s = Path(dp, name)
            if os.path.islink(s):
                raise UnsafeRoot(f"refusing source file: {s.name}")
            if s.suffix.lower() not in allowed_suffixes:
                if skip_others:  # license texts etc. shipped next to fonts: never copied
                    continue
                raise UnsafeRoot(f"refusing source file: {s.name}")
            (dst / rel / name).write_bytes(s.read_bytes())  # read+write: never copies a link


@contextlib.contextmanager
def build_workspace(
    *,
    template_dir: Path = TEMPLATES_DIR,
    font_dirs: tuple[Path, ...] | None = None,
    extra_files: Mapping[str, bytes] | None = None,
    allowed_suffixes=ALLOWED_SUFFIXES,
) -> Iterator[Workspace]:
    """Create a temp workspace; always removed on exit. ``extra_files`` (relative path ->
    bytes) lets tests add a throw-away template; it is validated like everything else."""
    base = Path(tempfile.mkdtemp(prefix="vg-pdf-"))
    try:
        os.chmod(base, 0o700)
        if _is_inside(base, PKG_DIR.parent.parent):
            raise UnsafeRoot("temp dir resolves inside the repository")
        root, home, pk, pc = (base / n for n in ("root", "home", "packages", "pkg-cache"))
        for d in (root, home, pk, pc):
            d.mkdir(mode=0o700)
        _copy_tree_plain(template_dir, root, allowed_suffixes=allowed_suffixes)
        fonts_out = root / "fonts"
        fonts_out.mkdir(exist_ok=True)
        if font_dirs is None:
            tf = template_dir / "fonts"
            font_dirs = (tf,) if tf.is_dir() and any(tf.glob("*.ttf")) else (LEGACY_FONTS_DIR,)
        for fd in font_dirs:
            _copy_tree_plain(Path(fd), fonts_out, allowed_suffixes=FONT_SUFFIXES, skip_others=True)
        for rel, data in (extra_files or {}).items():
            rp = Path(rel)
            if rp.is_absolute() or ".." in rp.parts:
                raise UnsafeRoot("bad extra file path")
            (root / rp).parent.mkdir(parents=True, exist_ok=True)
            (root / rp).write_bytes(data)
        verify_root(root, allowed_suffixes=allowed_suffixes)
        yield Workspace(base, root, home, pk, pc)
    finally:
        shutil.rmtree(base, ignore_errors=True)
