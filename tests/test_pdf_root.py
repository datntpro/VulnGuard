"""FS confinement: symlink-free private root, no absolute/.. escape (plan §5 F1-F3)."""
import os
from pathlib import Path

import pytest

from scanner.pdf.engine import run_worker
from scanner.pdf.errors import PdfCompileError, UnsafeRoot
from scanner.pdf.root import build_workspace, verify_root
from tests._pdf_helpers import compile_src, pdf_text


@pytest.fixture
def canary(tmp_path):
    p = tmp_path / "outside" / "secret.txt"
    p.parent.mkdir()
    p.write_text("SECRET-OUTSIDE-CANARY")
    return p


@pytest.mark.parametrize(
    "expr",
    [
        '#read("/etc/hosts")',
        '#image("/etc/passwd")',
        '#read("file:///etc/hosts")',
        '#read("../outside/secret.txt")',
        '#read("sub/../../outside/secret.txt")',
        '#read("@canary")',
    ],
)
def test_absolute_and_dotdot_reads_fail(expr, canary):
    expr = expr.replace("@canary", str(canary))
    with pytest.raises(PdfCompileError) as ei:
        compile_src(expr)
    assert "SECRET-OUTSIDE-CANARY" not in str(ei.value)


def test_absolute_canary_path_does_not_resolve_outside_root(canary):
    with pytest.raises(PdfCompileError):
        compile_src(f'#read("{canary}")')


def test_verify_root_refuses_symlink(tmp_path, canary):
    root = tmp_path / "r"
    root.mkdir()
    (root / "a.typ").write_text("x")
    os.symlink(canary, root / "link.typ")
    with pytest.raises(UnsafeRoot):
        verify_root(root)


def test_verify_root_refuses_symlinked_dir_and_hardlink(tmp_path, canary):
    root = tmp_path / "r"
    root.mkdir()
    os.symlink(canary.parent, root / "d")
    with pytest.raises(UnsafeRoot):
        verify_root(root)
    root2 = tmp_path / "r2"
    root2.mkdir()
    src = tmp_path / "h.typ"
    src.write_text("x")
    os.link(src, root2 / "h.typ")
    with pytest.raises(UnsafeRoot):
        verify_root(root2)


def test_verify_root_refuses_unexpected_file_types(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (root / "x.json").write_text("{}")
    with pytest.raises(UnsafeRoot):
        verify_root(root)


def test_build_workspace_refuses_symlinked_template_source(tmp_path, canary):
    tpl = tmp_path / "tpl"
    tpl.mkdir()
    (tpl / "report.typ").write_text("x")
    os.symlink(canary, tpl / "evil.typ")
    with pytest.raises(UnsafeRoot):
        with build_workspace(template_dir=tpl, font_dirs=()):
            pass


def test_workspace_has_only_expected_files_and_is_removed():
    with build_workspace() as ws:
        base = ws.base
        assert (base.stat().st_mode & 0o777) == 0o700
        files = {p.relative_to(ws.root).as_posix() for p in ws.root.rglob("*") if p.is_file()}
        assert "report.typ" in files
        assert all(f.endswith((".typ", ".ttf", ".otf", ".png")) for f in files)
        assert not any(p.is_symlink() for p in ws.root.rglob("*"))
        assert list(ws.packages.iterdir()) == [] and list(ws.pkg_cache.iterdir()) == []
        # never under the repo or storage/
        repo = Path(__file__).resolve().parent.parent
        assert repo not in base.resolve().parents
    assert not base.exists()


def test_workspace_removed_on_error():
    with pytest.raises(RuntimeError):
        with build_workspace() as ws:
            base = ws.base
            raise RuntimeError("boom")
    assert not base.exists()


def test_typst_follows_symlinks_hence_root_must_be_symlink_free(canary):
    """Pins probe F3 (typst 0.15.x): a symlink inside root DOES leak. If this ever fails
    after a typst upgrade, re-read the plan §5 before relaxing anything."""
    with build_workspace(extra_files={"t.typ": b'#read("link.typ")'}) as ws:
        os.symlink(canary, ws.root / "link.typ")  # bypasses build-time verify on purpose
        with pytest.raises(UnsafeRoot):
            verify_root(ws.root)  # ...which is exactly what verify catches
        pdf = run_worker(ws, {}, entry="t.typ")
        assert "SECRET-OUTSIDE-CANARY" in pdf_text(pdf)


def test_font_dir_license_and_other_files_not_copied(tmp_path):
    fd = tmp_path / "fonts"
    fd.mkdir()
    src = Path(__file__).resolve().parent.parent / "scanner" / "pdf" / "templates" / "fonts" / "DejaVuSans.ttf"
    (fd / "DejaVuSans.ttf").write_bytes(src.read_bytes())
    (fd / "OFL.txt").write_text("license")
    (fd / "README.md").write_text("x")
    (fd / "notes.json").write_text("{}")
    with build_workspace(font_dirs=(fd,)) as ws:  # verify_root must pass
        names = sorted(p.name for p in (ws.root / "fonts").iterdir())
        assert names == ["DejaVuSans.ttf"]


def test_font_dir_symlink_still_refused(tmp_path, canary):
    fd = tmp_path / "fonts"
    fd.mkdir()
    os.symlink(canary, fd / "x.ttf")
    with pytest.raises(UnsafeRoot):
        with build_workspace(font_dirs=(fd,)):
            pass


@pytest.mark.parametrize("n", range(8))  # was flaky on macOS (set iteration order)
def test_compile_error_does_not_leak_temp_path(n):
    import tempfile

    with pytest.raises(PdfCompileError) as ei:
        compile_src('#read("missing-file.typ")')
    msg = str(ei.value)
    assert "vg-pdf-" not in msg and tempfile.gettempdir() not in msg and "/private" not in msg
    assert msg  # still informative


def test_scrub_paths_both_var_and_private_forms(tmp_path):
    from scanner.pdf.engine import _scrub_paths
    from scanner.pdf.root import Workspace

    base = tmp_path / "vg-pdf-abc"
    base.mkdir()
    root = base / "root"
    root.mkdir()
    ws = Workspace(base, root, base, base, base)
    for _ in range(20):
        for form in (str(base), str(base.resolve()), "/private" + str(base)):
            out = _scrub_paths(f"searched at {form}/root/hosts", ws)
            assert "/private" not in out and "vg-pdf-" not in out
