"""Reachability probe for scanner-lock advisories (#101 PR-C).

Loaded through PYTHONPATH by check.py. Records every *call* into watched
third-party code and classifies it IMPORT (some ancestor frame is a module body,
i.e. executing during import) or RUN (executing during real work). At exit it
dumps the RUN calls to $VG_PROBE_OUT (default stderr). Stdlib only, no side effects
on the scanned program.
"""
import atexit
import os
import sys
import threading

_WATCH = [w for w in os.environ.get("VG_PROBE_WATCH", "").split(",") if w]
_OUT = os.environ.get("VG_PROBE_OUT")
_RUN = {}
_LOADED = {"pid": os.getpid()}


def _is_import(frame):
    f = frame.f_back
    while f is not None:
        if f.f_code.co_name == "<module>":
            return True
        f = f.f_back
    return False


def _profile(frame, event, arg):
    if event != "call":
        return
    code = frame.f_code
    name = code.co_name
    if name == "<module>":
        return
    fn = code.co_filename
    for w in _WATCH:
        if w in fn:
            if not _is_import(frame):
                key = f"{fn.split('site-packages/')[-1]}:{name}"
                _RUN[key] = _RUN.get(key, 0) + 1
            return


def _dump():
    sys.setprofile(None)
    lines = [f"loaded pid={_LOADED['pid']}"]
    lines += [f"RUN {k} x{v}" for k, v in sorted(_RUN.items())]
    text = "\n".join(lines) + "\n"
    if _OUT:
        with open(_OUT, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stderr.write(text)


if _WATCH:
    # Marker at import so "probe loaded" is provable even when the program dies early.
    if _OUT:
        with open(_OUT, "a", encoding="utf-8") as fh:
            fh.write(f"loaded pid={os.getpid()}\n")
    sys.setprofile(_profile)
    threading.setprofile(_profile)
    atexit.register(_dump)
