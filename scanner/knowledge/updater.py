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


def _atomic_swap(new_file: str, dest: str) -> None:
    """Thay dest bằng new_file nguyên khối; giữ bản .bak để rollback."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        shutil.copy2(dest, dest + ".bak")
    os.replace(new_file, dest)   # atomic trên cùng filesystem


def import_file(src_path: str, dest_path: str, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
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
            with gzip.open(src_path, "rb") as fi, open(tmp.name, "wb") as fo:
                shutil.copyfileobj(fi, fo)
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
    Luồng online đầy đủ: đọc manifest → so version → tải → verify → swap.
    Trả {updated: bool, from, to, reason}. KHÔNG raise ra ngoài (trả reason lỗi).
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
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as c:
            raw = c.get(manifest_url).raise_for_status().content
            # Xác thực chữ ký TRƯỚC khi parse bất cứ thứ gì từ manifest.
            sig_resp = c.get(manifest_url + ".sig")
            if sig_resp.status_code == 200:
                if not verify_manifest_signature(raw, sig_resp.content):
                    return {"updated": False, "from": local_ver,
                            "reason": "chữ ký manifest không hợp lệ"}
            elif settings.kb_require_signature:
                return {"updated": False, "from": local_ver,
                        "reason": "manifest thiếu chữ ký (.sig) — bị từ chối"}
            else:
                log.warning("KB manifest không có chữ ký (kb_require_signature=false) — chấp nhận không xác thực")
            m = json.loads(raw)
            validate_manifest(m)
            # Chống rollback: không bao giờ hạ cấp KB, kể cả force / manifest cũ được replay.
            if local_ver and _ver_tuple(m["version"]) < _ver_tuple(local_ver):
                return {"updated": False, "from": local_ver, "to": m["version"],
                        "reason": "từ chối hạ cấp KB (rollback)"}
            if not force and not needs_update(local_ver, m["version"]):
                return {"updated": False, "from": local_ver, "to": m["version"],
                        "reason": "đã mới nhất"}
            # tải snapshot
            r = c.get(m["url"]).raise_for_status()
            d = os.path.dirname(dest_path) or "."
            os.makedirs(d, exist_ok=True)
            dl = tempfile.NamedTemporaryFile(delete=False, dir=d, suffix=".gz")
            dl.write(r.content)
            dl.close()
    except Exception as e:
        return {"updated": False, "from": local_ver, "reason": f"lỗi tải/manifest: {str(e)[:150]}"}

    try:
        import_file(dl.name, dest_path, expected_sha256=m["sha256"])
    except Exception as e:
        return {"updated": False, "from": local_ver, "to": m.get("version"),
                "reason": f"lỗi verify/import: {str(e)[:150]}"}
    finally:
        if os.path.exists(dl.name):
            os.unlink(dl.name)
    return {"updated": True, "from": local_ver, "to": m["version"], "reason": "đã cập nhật"}
