"""Giải nén mã nguồn benchmark bên thứ ba (XBOW / AutoPenBench) một cách TỐI THIỂU và có dọn dẹp.

  * `extract_selected`: chỉ ghi những thành viên nằm dưới ĐÚNG các thư mục đã chọn (`<top>/benchmarks/<id>/...`) — không bao giờ ghi
    `xben-benchmark-results/` hay thư mục upstream khác (báo cáo mẫu đầy payload tấn công làm Defender/AV xoá file); chỉ file/thư mục thường
    (bỏ symlink/hardlink/thiết bị); từ chối đường dẫn tuyệt đối / `..`; kiểm tra tên thư mục gốc của tarball khớp SHA đã ghim.
  * `cache_dir`: thư mục tạm NẰM TRONG repo (gitignored `eval/lab/src-cache/`, KHÔNG phải $TMPDIR) và luôn bị xoá (try/finally)."""
import contextlib
import os
import shutil
import tarfile
import tempfile
from typing import Iterable, Iterator, List

CACHE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lab", "src-cache"))


@contextlib.contextmanager
def cache_dir(prefix: str, root: str = "") -> Iterator[str]:
    root = root or CACHE_ROOT
    os.makedirs(root, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=root)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _unsafe(rel: str) -> bool:
    return not rel or os.path.isabs(rel) or ".." in rel.split("/") or "\\" in rel or "\0" in rel


def extract_selected(tar: tarfile.TarFile, top: str, allowed: Iterable[str], dest: str) -> List[str]:
    """Giải nén từ `tar` (có thể là stream `r|gz`) vào `dest` CHỈ các thành viên có đường dẫn tương đối (sau `top/`) bắt đầu bằng một
    trong `allowed` (mỗi phần tử là thư mục kết thúc bằng '/' hoặc đường dẫn file đầy đủ). Trả danh sách đường dẫn tương đối đã ghi."""
    allowed = tuple(allowed)
    written: List[str] = []
    seen_top = False
    for m in tar:
        head, _, rel = m.name.partition("/")
        if not seen_top:
            if head != top:
                raise ValueError(f"tarball không phải {top!r} (thư mục gốc {head!r}) — từ chối (SHA ghim không khớp)")
            seen_top = True
        if head != top or not rel.startswith(allowed):
            continue
        if _unsafe(rel):
            raise ValueError(f"đường dẫn lạ trong tarball: {m.name!r}")
        if not (m.isfile() or m.isdir()):          # symlink / hardlink / thiết bị: không bao giờ ghi
            continue
        tar.extract(m, dest, filter="data")
        written.append(rel)
    if not seen_top:
        raise ValueError("tarball rỗng")
    return written
