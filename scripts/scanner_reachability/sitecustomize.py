"""Reachability probe for scanner-lock advisories (#101 PR-C).

Loaded through PYTHONPATH by check.py. Records every *call* into watched third-party code and
classifies it:
  IMPORT - the call happens while the import machinery is on the stack (a `<frozen importlib...>`
           frame such as _find_and_load / exec_module is an ancestor), i.e. module-level code.
  RUN    - everything else, including main-thread work started from a console-script `<module>`
           frame (`sys.exit(main())`). NOTE: a `<module>` ancestor does NOT mean import time.
At exit the per-key counts are dumped to $VG_PROBE_OUT (default stderr). Stdlib only.
"""
import atexit
import os
import sys
import threading

_WATCH = [w for w in os.environ.get("VG_PROBE_WATCH", "").split(",") if w]
_OUT = os.environ.get("VG_PROBE_OUT")
_RUN = {}
_IMP = {}


def _is_import(frame):
    f = frame.f_back
    while f is not None:
        if f.f_code.co_filename.startswith("<frozen importlib"):
            return True
        f = f.f_back
    return False


def _profile(frame, event, arg):
    if event != "call":
        return
    code = frame.f_code
    if code.co_name == "<module>":
        return
    fn = code.co_filename
    for w in _WATCH:
        if w in fn:
            key = f"{fn.split('site-packages/')[-1]}:{code.co_name}"
            bucket = _IMP if _is_import(frame) else _RUN
            bucket[key] = bucket.get(key, 0) + 1
            return


def _emit(text):
    if _OUT:
        with open(_OUT, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stderr.write(text)


def _dump():
    sys.setprofile(None)
    lines = [f"loaded pid={os.getpid()}"]
    lines += [f"IMPORT {k} x{v}" for k, v in sorted(_IMP.items())]
    lines += [f"RUN {k} x{v}" for k, v in sorted(_RUN.items())]
    _emit("\n".join(lines) + "\n")


if _WATCH:
    _emit(f"loaded pid={os.getpid()}\n")  # marker even if the process dies before atexit
    sys.setprofile(_profile)
    threading.setprofile(_profile)
    atexit.register(_dump)
