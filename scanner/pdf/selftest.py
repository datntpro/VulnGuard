"""PDF engine self-test: ``python -m scanner.pdf.selftest`` (run from the repo root; not ``-I``, which hides the cwd) (Docker build, setup.py, run.sh).

Renders a 1-page Vietnamese document through the hardened worker and checks:
  1. the ``%PDF-`` magic;
  2. the extracted text contains "Đối tượng kiểm thử" (U+0110, not U+00D0);
  3. every embedded font is Type0/FontFile2 and belongs to our bundled set;
  4. a ``@preview`` package import FAILS (network kill-switch active).
On failure prints *why* plus a fix command and exits 1. No network, no browser required.
"""
from __future__ import annotations

import io
import re
import sys
from typing import Callable

FIX_HINT = (
    "Fix: reinstall the lockfile -> `pip install --require-hashes -r api/requirements.txt` "
    "(native: `bash setup.sh`; Docker: `docker compose build --no-cache`). "
    "Windows ARM64 has no typst wheel: use x64 Python or Docker."
)
ALLOWED_FONT = re.compile(r"^(DejaVuSans(-Bold)?|DejaVuSansMono|BeVietnamPro-.*|JetBrainsMono-.*)$")
# built from code points so no bidi-control literal appears in source (bandit B613)
_STRIP = re.compile("[\\s" + "".join(chr(c) for c in (0x200B, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF)) + "]")
PHRASE = "Đối tượng kiểm thử"


class SelfTestError(Exception):
    pass


def engine_version() -> str:
    try:
        import typst
    except Exception as e:  # noqa: BLE001
        raise SelfTestError(f"typst wheel not importable ({type(e).__name__}: {e})") from e
    return str(getattr(typst, "__version__", "unknown"))


def _render() -> bytes:
    from .engine import render

    doc = {
        "title": PHRASE,
        "findings": [{"title": "Nghiêm trọng", "description": "Khắc phục: Ư Ơ ỹ ặ ẫ", "code": "=> != ->"}],
    }
    return render("scan", doc, generated_at=0, timeout_s=60)


def check_render() -> bytes:
    try:
        pdf = _render()
    except Exception as e:  # noqa: BLE001
        raise SelfTestError(f"render failed: {type(e).__name__}: {e}") from e
    if not pdf.startswith(b"%PDF-"):
        raise SelfTestError("output lacks %PDF- magic")
    return pdf


def check_text(pdf: bytes) -> None:
    from pypdf import PdfReader

    text = "".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf)).pages)
    flat = _STRIP.sub("", text)
    if _STRIP.sub("", PHRASE) not in flat:
        raise SelfTestError(f"Vietnamese text not extracted correctly (got {flat[:60]!r})")
    if "Ð" in text:
        raise SelfTestError("U+00D0 found: Đ mapped to wrong glyph (font issue)")


def check_fonts(pdf: bytes) -> None:
    from pypdf import PdfReader

    seen = 0
    for page in PdfReader(io.BytesIO(pdf)).pages:
        for f in ((page["/Resources"].get("/Font")) or {}).values():
            f = f.get_object()
            seen += 1
            if f.get("/Subtype") != "/Type0":
                raise SelfTestError(f"font {f.get('/BaseFont')} is {f.get('/Subtype')}, expected Type0")
            desc = f["/DescendantFonts"][0].get_object()["/FontDescriptor"].get_object()
            if "/FontFile2" not in desc:
                raise SelfTestError(f"font {f.get('/BaseFont')} not embedded as FontFile2")
            base = re.sub(r"^[A-Z]{6}\+", "", str(f["/BaseFont"]).lstrip("/"))
            if not ALLOWED_FONT.match(base):
                raise SelfTestError(f"unexpected font {base!r} (fonts missing from the image/package?)")
    if not seen:
        raise SelfTestError("no fonts embedded")


def check_no_network() -> None:
    from .engine import run_worker
    from .errors import PdfEngineError
    from .root import build_workspace

    src = b'#import "@preview/tablex:0.0.9": tablex\nok'
    try:
        with build_workspace(extra_files={"t.typ": src}) as ws:
            run_worker(ws, {}, entry="t.typ", timeout_s=30)
    except PdfEngineError:
        return
    except Exception as e:  # noqa: BLE001
        raise SelfTestError(f"unexpected error in package probe: {type(e).__name__}") from e
    raise SelfTestError("@preview import succeeded: network/package kill-switch NOT active")


def run_all() -> list[tuple[str, str | None]]:
    """Return [(check, error-or-None)]. A failed render skips the dependent checks."""
    results: list[tuple[str, str | None]] = []

    def step(name: str, fn: Callable[[], object]):
        try:
            out = fn()
            results.append((name, None))
            return out
        except SelfTestError as e:
            results.append((name, str(e)))
        except Exception as e:  # noqa: BLE001
            results.append((name, f"{type(e).__name__}: {e}"))
        return None

    ver = step("import typst", engine_version)
    if ver is None:
        return results
    pdf = step("render 1-page VN pdf (hardened worker)", check_render)
    if pdf is not None:
        step("text extraction (Đối tượng kiểm thử)", lambda: check_text(pdf))
        step("fonts embedded (Type0/FontFile2, bundled set)", lambda: check_fonts(pdf))
    step("@preview import blocked (no network)", check_no_network)
    return results


def main(argv: list[str] | None = None) -> int:
    quiet = "--quiet" in (argv if argv is not None else sys.argv[1:])
    results = run_all()
    failed = [(n, e) for n, e in results if e]
    if not quiet or failed:
        for n, e in results:
            print(("  ok   " if e is None else "  FAIL ") + n + ("" if e is None else f": {e}"))
    try:
        ver = engine_version()
    except SelfTestError:
        ver = "missing"
    if failed:
        print(f"PDF engine: typst {ver} FAILED ({len(failed)} check(s)). {FIX_HINT}", file=sys.stderr)
        return 1
    print(f"PDF engine: typst {ver} OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
