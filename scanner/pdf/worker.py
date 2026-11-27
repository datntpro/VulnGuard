"""Typst compile worker. Run as ``python -I <this file> '<limits-json>'`` (stand-alone: only
stdlib + ``typst`` are imported, so ``-I`` isolated mode works without our package on sys.path).

stdin : 4-byte big-endian length + JSON job
stdout: raw PDF bytes (nothing else)
stderr: one short error line on failure
exit  : 0 ok, 2 compile error, 3 bad job, 4 resource limit
"""
import json
import os
import struct
import sys

MAX_JOB = 64 * 1024 * 1024


def _set_limits(lim):
    try:
        import resource
    except ImportError:  # Windows: parent watchdog + RSS poll only
        return
    def setl(which, value):
        try:
            _s, hard = resource.getrlimit(which)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError):
            pass  # not enforceable here (macOS RLIMIT_AS): parent RSS poll covers it
    if lim.get("as_bytes"):
        setl(resource.RLIMIT_AS, int(lim["as_bytes"]))
    if lim.get("cpu_s"):
        setl(resource.RLIMIT_CPU, int(lim["cpu_s"]))
    setl(resource.RLIMIT_CORE, 0)
    if lim.get("nofile"):
        setl(resource.RLIMIT_NOFILE, int(lim["nofile"]))
    if hasattr(resource, "RLIMIT_FSIZE") and lim.get("fsize") is not None:
        setl(resource.RLIMIT_FSIZE, int(lim["fsize"]))


def _read_job():
    hdr = sys.stdin.buffer.read(4)
    if len(hdr) != 4:
        raise ValueError("short header")
    (n,) = struct.unpack(">I", hdr)
    if n > MAX_JOB:
        raise ValueError("job too large")
    buf = sys.stdin.buffer.read(n)
    if len(buf) != n:
        raise ValueError("short job")
    return json.loads(buf)


def main():
    lim = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    _set_limits(lim)
    try:
        job = _read_job()
        entry, root = job["entry"], job["root"]
        inputs = {str(k): str(v) for k, v in job["inputs"].items()}
        fonts_dir = job["fonts_dir"]
        packages, cache = job["packages"], job["pkg_cache"]
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("bad job: %s\n" % type(e).__name__)
        return 3
    try:
        import typst
        fonts = typst.Fonts(include_system_fonts=False, include_embedded_fonts=False, font_paths=[fonts_dir])
        pdf = typst.compile(
            os.path.join(root, entry),
            root=root,
            format="pdf",
            font_paths=fonts,
            sys_inputs=inputs,
            package_path=packages,
            package_cache_path=cache,
            timestamp=job.get("timestamp"),
            pdf_tags=True,
        )
    except MemoryError:
        sys.stderr.write("out of memory\n")
        return 4
    except Exception as e:  # noqa: BLE001
        msg = str(getattr(e, "message", e)).replace("\n", " ")[:600]
        sys.stderr.write("%s: %s\n" % (type(e).__name__, msg))
        return 2
    out = sys.stdout.buffer
    out.write(pdf)
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
