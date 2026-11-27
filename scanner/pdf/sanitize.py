"""Sanitise untrusted strings before they are serialised into ``sys.inputs`` JSON.

This is defence in depth: the *safety* of the pipeline comes from "data is a value, never
source" (see tests/test_pdf_injection.py); sanitising removes characters that make a PDF
misleading (bidi overrides) or break text extraction (C0/C1 controls), and inserts
zero-width wrap points so a 3000-char token cannot overflow a table cell.
"""
from __future__ import annotations

import re
from typing import Any

ZWSP = "​"
WRAP_EVERY = 60
MAX_DEPTH = 12

# C0 except \t \n ; DEL; C1; bidi embeddings/overrides/isolates; BOM; zero-width joiners of
# the attack kind are left alone (needed for some scripts) but U+200B is normalised below.
_CONTROLS = re.compile(
    "[\u0000-\u0008\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩﻿‎‏؜]"
)
_ZWSP = re.compile(ZWSP)
_LONG_RUN = re.compile(r"[^\s​]{%d,}" % (WRAP_EVERY + 1))


def _wrap_run(m: "re.Match[str]") -> str:
    s = m.group(0)
    return ZWSP.join(s[i : i + WRAP_EVERY] for i in range(0, len(s), WRAP_EVERY))


def clean_text(s: str, *, max_len: int | None = None, wrap: bool = True) -> str:
    """Strip controls/bidi/BOM, optionally truncate, optionally insert wrap points."""
    s = _CONTROLS.sub("", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _ZWSP.sub("", s)  # never trust incoming ZWSP; we add our own
    if max_len is not None and len(s) > max_len:
        s = s[: max(0, max_len - 1)] + "…"
    if wrap:
        s = _LONG_RUN.sub(_wrap_run, s)
    return s


def sanitize(value: Any, *, max_str: int = 8192, _depth: int = 0) -> Any:
    """Recursively sanitise a JSON-able structure. Keys are kept as-is if they are plain
    identifiers, otherwise sanitised; non-JSON types are rejected by the caller."""
    if _depth > MAX_DEPTH:
        raise ValueError("document nesting too deep")
    if isinstance(value, str):
        return clean_text(value, max_len=max_str)
    if isinstance(value, dict):
        return {
            (k if isinstance(k, str) and k.isidentifier() else clean_text(str(k), max_len=100, wrap=False)):
            sanitize(v, max_str=max_str, _depth=_depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(v, max_str=max_str, _depth=_depth + 1) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"unsupported type in report document: {type(value).__name__}")
