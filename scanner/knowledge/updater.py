"""
Cập nhật Knowledge Base ở MÁY ĐÃ CÀI (client) — tải snapshot KB vendor publish rồi
swap atomically. Mô hình giống Trivy DB / nuclei-templates:

  vendor CI build hàng ngày → publish kb.sqlite.gz + kb-manifest.json (GitHub Releases)
  máy khách: đọc manifest → so version → tải .gz → verify sha256 → giải nén → swap.

Không tải gì nếu version local đã >= remote. An toàn offline: import_file() cho air-gap.
Các hàm so sánh/verify là pure (test được không cần mạng).
"""
import gzip
import hashlib
import json
import os
import shutil
import tempfile
import base64
import datetime
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Khóa công khai Ed25519 (raw 32 byte, base64) của owner — dùng verify chữ ký manifest KB.
# Là danh sách để xoay khóa: thêm khóa mới trước, bỏ khóa cũ sau.
# Khóa riêng nằm ở GitHub secret KB_SIGNING_KEY (chỉ workflow kb-build dùng).
KB_PUBLIC_KEYS: List[str] = [
    "LcSouBEA4B0fZio4pRRPreABp83GXY2JWKmJgPVclHs=",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ver_tuple(v: str):
    """'2026.11.24' → (2026,11,24); chuỗi lạ → (0,) để luôn 'cũ hơn'."""
    try:
        return tuple(int(x) for x in str(v).replace("-", ".").split("."))
    except Exception:
        return (0,)


def needs_update(local_version: Optional[str], remote_version: Optional[str]) -> bool:
    """True nếu remote mới hơn local (hoặc local chưa có)."""
    if not remote_version:
        return False
    if not local_version:
        return True
    return _ver_tuple(remote_version) > _ver_tuple(local_version)


def validate_manifest(m: Dict[str, Any]) -> None:
    """Bắt buộc có version, sha256, url. Raise ValueError nếu thiếu/không hợp lệ."""
    for k in ("version", "sha256", "url"):
        if not m.get(k):
            raise ValueError(f"manifest thiếu trường '{k}'")
    if len(str(m["sha256"])) != 64:
        raise ValueError("sha256 không hợp lệ (cần 64 hex)")


def verify_manifest_signature(data: bytes, sig_b64: bytes) -> bool:
    """True nếu sig (base64 Ed25519) là chữ ký hợp lệ của `data` bởi BẤT KỲ khóa trong KB_PUBLIC_KEYS."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except Exception:
        return False
    for k in KB_PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(sig, data)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


MAX_MANIFEST_BYTES = 64 << 10
MAX_SIG_BYTES = 1 << 10
MAX_SNAPSHOT_BYTES = 1 << 30
_MAX_FUTURE_DAYS = 2


def _sigstate_path(dest_path: str) -> str:
    return dest_path + ".sigstate"


def _read_sigstate_checked(dest_path: str):
    """(state, corrupt). corrupt=True nếu sidecar TỒN TẠI nhưng không đọc/thiếu signed_version
    → coi như 'đã từng thấy bản ký' (fail closed)."""
    path = _sigstate_path(dest_path)
    if not os.path.exists(path):
        return {}, False
    try:
        with open(path) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("signed_version"), str) and d["signed_version"]:
            return d, False
    except Exception:
        pass
    log.error("KB .sigstate hỏng/không hợp lệ — coi như đã từng cài bản ký (bắt buộc chữ ký)")
    return {}, True


def _read_sigstate(dest_path: str) -> Dict[str, Any]:
    """Trạng thái chỉ-ghi-khi-đã-verify-chữ-ký: {signed_version, signed_built_at}."""
    return _read_sigstate_checked(dest_path)[0]


def _write_sigstate(dest_path: str, version: str, built_at: Optional[str]) -> None:
    """Ghi nguyên tử: tmp + fsync + rename (+ fsync thư mục)."""
    path = _sigstate_path(dest_path)
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".sigstate.tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"signed_version": version, "signed_built_at": built_at}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    try:
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def _version_in_future(v: str) -> bool:
    """Version dạng YYYY.MM.DD không được ở tương lai quá _MAX_FUTURE_DAYS (chống đầu độc sàn rollback)."""
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=_MAX_FUTURE_DAYS)
    return _ver_tuple(v)[:3] > (now.year, now.month, now.day)


def _is_stale(built_at: Optional[str], max_days: int) -> bool:
    try:
        t = datetime.datetime.fromisoformat(str(built_at).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return True   # signed manifest không có built_at hợp lệ → coi là cũ
    return (datetime.datetime.now(datetime.timezone.utc) - t).days > max_days


def _fetch(c, url: str, cap: int, accept_404: bool = False):
    """GET có giới hạn byte (stream). Trả (status, bytes). Status khác 200 (trừ 404 nếu accept_404) → raise."""
    with c.stream("GET", url) as r:
        if r.status_code == 404 and accept_404:
            return 404, b""
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} khi tải {url.rsplit('/', 1)[-1]}")
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > cap:
                raise RuntimeError(f"phản hồi vượt giới hạn {cap} byte")
        return 200, bytes(buf)


def _atomic_swap(new_file: str, dest: str) -> None:
    """Thay dest bằng new_file nguyên khối; giữ bản .bak để rollback."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        shutil.copy2(dest, dest + ".bak")
    os.replace(new_file, dest)   # atomic trên cùng filesystem


def _max_uncompressed() -> int:
    try:
        from api.config import settings
        return int(settings.upload_max_uncompressed_bytes)
    except Exception:
        return 2 << 30


def import_file(src_path: str, dest_path: str, expected_sha256: Optional[str] = None,
                max_uncompressed: Optional[int] = None) -> Dict[str, Any]:
    """
    Import KB từ file local (offline/air-gap). Chấp nhận .sqlite hoặc .gz.
    Verify sha256 (của file như-đã-tải) nếu được cung cấp, rồi swap.
    """
    from scanner.knowledge.store import get_meta
    if expected_sha256:
        got = sha256_file(src_path)
        if got.lower() != expected_sha256.lower():
            raise ValueError(f"sha256 không khớp: {got} != {expected_sha256}")
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(dest_path) or ".",
                                      suffix=".tmp")
    tmp.close()
    try:
        if src_path.endswith(".gz"):
            cap = max_uncompressed or _max_uncompressed()
            total = 0
            with gzip.open(src_path, "rb") as fi, open(tmp.name, "wb") as fo:
                for chunk in iter(lambda: fi.read(1 << 20), b""):
                    total += len(chunk)
                    if total > cap:   # gzip bomb
                        raise ValueError("giải nén vượt giới hạn kích thước (gzip bomb?)")
                    fo.write(chunk)
        else:
            shutil.copy2(src_path, tmp.name)
        # sanity: phải mở được & có bảng advisory
        meta = get_meta(tmp.name)
        if not meta.get("available"):
            raise ValueError("file KB không hợp lệ (không đọc được advisory)")
        _atomic_swap(tmp.name, dest_path)
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    return get_meta(dest_path)


def check_and_update(manifest_url: Optional[str] = None, dest_path: Optional[str] = None,
                     force: bool = False) -> Dict[str, Any]:
    """
    Luồng online đầy đủ: đọc manifest → verify chữ ký → so version → tải → verify sha → swap.
    Trả {updated: bool, from, to, reason}. KHÔNG raise ra ngoài (trả reason lỗi).

    Chữ ký:
      - .sig = 200 → phải hợp lệ. 404 → "chưa ký" (chỉ chấp nhận khi kb_require_signature=false
        VÀ máy này chưa từng cài bản đã ký). Mọi lỗi khác (5xx/403/timeout…) → từ chối, giữ KB cũ.
      - Sàn anti-rollback chỉ lấy từ manifest ĐÃ verify (sidecar .sigstate), không lấy từ meta DB.
    """
    import httpx
    from api.config import settings
    from scanner.knowledge.store import kb_path, get_meta

    manifest_url = manifest_url or settings.kb_manifest_url
    dest_path = dest_path or kb_path()
    if not manifest_url:
        return {"updated": False, "reason": "chưa cấu hình kb_manifest_url"}

    local = get_meta(dest_path)
    local_ver = local.get("version") if local.get("available") else None
    state, corrupt = _read_sigstate_checked(dest_path)
    floor = state.get("signed_version")
    # Sticky: đã từng cài bản ký (sidecar hợp lệ, sidecar hỏng, hoặc cờ trong meta KB) → bắt buộc chữ ký.
    sticky = bool(floor) or corrupt or bool(local.get("signed_seen"))
    stale = False
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as c:
            _, raw = _fetch(c, manifest_url, MAX_MANIFEST_BYTES)
            # Xác thực chữ ký TRƯỚC khi parse bất cứ thứ gì từ manifest.
            code, sig = _fetch(c, manifest_url + ".sig", MAX_SIG_BYTES, accept_404=True)
            signed = code == 200
            if signed:
                if not verify_manifest_signature(raw, sig):
                    return {"updated": False, "from": local_ver,
                            "reason": "chữ ký manifest không hợp lệ"}
            elif settings.kb_require_signature or sticky:
                return {"updated": False, "from": local_ver,
                        "reason": "manifest thiếu chữ ký (.sig) — bị từ chối"}
            else:
                log.warning("KB manifest không có chữ ký (kb_require_signature=false) — chấp nhận không xác thực")
            m = json.loads(raw)
            validate_manifest(m)
            ver = str(m["version"])
            if _version_in_future(ver):
                return {"updated": False, "from": local_ver, "to": ver,
                        "reason": "version manifest ở tương lai — bị từ chối"}
            if signed:
                stale = _is_stale(m.get("built_at"), settings.kb_max_manifest_age_days)
                if stale:
                    log.warning("KB manifest đã ký nhưng built_at cũ > %s ngày (có thể bị giữ bản cũ — freeze)",
                                settings.kb_max_manifest_age_days)
                # Sàn rollback: chỉ từ bản đã verify.
                if floor and _ver_tuple(ver) < _ver_tuple(floor):
                    return {"updated": False, "from": local_ver, "to": ver,
                            "reason": "từ chối hạ cấp KB (rollback)", "stale": stale}
                same = bool(floor) and _ver_tuple(ver) == _ver_tuple(floor)
                if same and str(m.get("built_at") or "") < str(state.get("signed_built_at") or ""):
                    return {"updated": False, "from": local_ver, "to": ver,
                            "reason": "từ chối bản build cũ hơn cùng version (replay)", "stale": stale}
                # Chưa có sàn đã-ký (vd. đang có bản chưa ký) → cài bản ký đầu tiên bất kể version local.
                need = (not floor) or (not local.get("available")) or _ver_tuple(ver) > _ver_tuple(floor) or \
                    (same and str(m.get("built_at") or "") > str(state.get("signed_built_at") or ""))
                if not force and not need:
                    return {"updated": False, "from": local_ver, "to": ver,
                            "reason": "đã mới nhất", "stale": stale}
            else:
                if local_ver and _ver_tuple(ver) < _ver_tuple(local_ver):
                    return {"updated": False, "from": local_ver, "to": ver,
                            "reason": "từ chối hạ cấp KB (rollback)"}
                if not force and not needs_update(local_ver, ver):
                    return {"updated": False, "from": local_ver, "to": ver, "reason": "đã mới nhất"}
            # tải snapshot (giới hạn byte)
            _, blob = _fetch(c, m["url"], MAX_SNAPSHOT_BYTES)
            if hashlib.sha256(blob).hexdigest() != str(m["sha256"]).lower():
                return {"updated": False, "from": local_ver, "to": ver, "reason": "lỗi verify/import: sha256 không khớp"}
            d = os.path.dirname(dest_path) or "."
            os.makedirs(d, exist_ok=True)
            dl = tempfile.NamedTemporaryFile(delete=False, dir=d, suffix=".gz")
            dl.write(blob)
            dl.close()
    except Exception as e:
        return {"updated": False, "from": local_ver, "reason": f"lỗi tải/manifest: {str(e)[:150]}"}

    try:
        import_file(dl.name, dest_path, expected_sha256=m["sha256"])
        if signed:
            from scanner.knowledge.store import set_meta
            set_meta(dest_path, signed_seen=True)   # dự phòng nếu sidecar bị xóa
            _write_sigstate(dest_path, ver, m.get("built_at"))
    except Exception as e:
        return {"updated": False, "from": local_ver, "to": m.get("version"),
                "reason": f"lỗi verify/import: {str(e)[:150]}"}
    finally:
        if os.path.exists(dl.name):
            os.unlink(dl.name)
    return {"updated": True, "from": local_ver, "to": ver, "reason": "đã cập nhật",
            "signed": signed, "stale": stale}
