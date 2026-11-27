"""Shared helpers for tests/test_pdf_*.py (test-only templates live in a temp root, never shipped)."""
import io
import json
import re

from pypdf import PdfReader

from scanner.pdf.engine import run_worker
from scanner.pdf.root import build_workspace

_STRIP = re.compile(r"[\s​‎‏‪-‮⁦-⁩﻿\u0000-\u001f]")


def norm(s: str) -> str:
    return _STRIP.sub("", s)


def pdf_text(pdf: bytes) -> str:
    return "".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf)).pages)


def compile_src(src: str, inputs=None, *, extra=None, **kw) -> bytes:
    """Compile a throw-away template inside the hardened worker."""
    files = {"t.typ": src.encode("utf-8")}
    files.update(extra or {})
    with build_workspace(extra_files=files) as ws:
        return run_worker(ws, inputs or {}, entry="t.typ", **kw)


def data_inputs(doc) -> dict:
    return {"data": json.dumps(doc, ensure_ascii=False)}
