"""PR-J: chữ ký Ed25519 cho manifest KB (throwaway keypair, KHÔNG dùng khóa thật)."""
import base64
import gzip
import hashlib
import json
import os
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scanner.knowledge import updater
from scanner.knowledge.store import get_meta
from tests.test_knowledge_base import _seed

URL = "https://example.test/kb-manifest.json"


def _pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _sign(k, data):
    return base64.b64encode(k.sign(data))


class _Stream:
    def __init__(self, status, content):
        self.status_code, self._c = status, content

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def iter_bytes(self):
        for i in range(0, len(self._c), 4096):
            yield self._c[i:i + 4096]


def _today(delta=0):
    import datetime
    return (datetime.date.today() + datetime.timedelta(days=delta)).strftime("%Y.%m.%d")


def _now_iso(days_ago=0):
    import datetime
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make(version=None, built_at=None, raw_blob=None):
    version = version or _today()
    built_at = built_at or _now_iso()
    d = tempfile.mkdtemp()
    src = os.path.join(d, "kb.sqlite")
    _seed(src)
    from scanner.knowledge.store import set_meta
    set_meta(src, version=version)
    gz = src + ".gz"
    with open(src, "rb") as fi, gzip.open(gz, "wb") as fo:
        fo.write(fi.read())
    blob = raw_blob if raw_blob is not None else open(gz, "rb").read()
    m = {"version": version, "built_at": built_at, "sha256": hashlib.sha256(blob).hexdigest(), "url": "https://example.test/kb.gz"}
    return json.dumps(m).encode(), blob


@pytest.fixture
def env(monkeypatch):
    import httpx
    from api.config import settings
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(updater, "KB_PUBLIC_KEYS", [_pub(key)])
    served = {}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, method, url):
            v = served.get(url, 404)
            if isinstance(v, Exception):
                raise v
            return _Stream(v if isinstance(v, int) else 200, b"" if isinstance(v, int) else v)

    monkeypatch.setattr(httpx, "Client", FakeClient)
    monkeypatch.setattr(settings, "kb_require_signature", True)
    dest = os.path.join(tempfile.mkdtemp(), "kb.sqlite")
    return key, served, dest, settings


def _serve(served, manifest, blob, sig=None):
    served[URL] = manifest
    served["https://example.test/kb.gz"] = blob
    if sig is not None:
        served[URL + ".sig"] = sig


def test_valid_signature_accepted(env):
    key, served, dest, _ = env
    man, blob = _make()
    _serve(served, man, blob, _sign(key, man))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is True, r
    assert get_meta(dest)["available"]


def test_tampered_manifest_rejected(env):
    key, served, dest, _ = env
    man, blob = _make()
    evil = man.replace(_today().encode(), _today(1).encode())
    _serve(served, evil, blob, _sign(key, man))   # chữ ký của bản gốc
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and "chữ ký" in r["reason"]
    assert not os.path.exists(dest)


def test_tampered_snapshot_rejected_by_signed_sha(env):
    key, served, dest, _ = env
    man, blob = _make()
    _serve(served, man, blob + b"x", _sign(key, man))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and not os.path.exists(dest)


def test_wrong_key_rejected(env):
    _, served, dest, _ = env
    man, blob = _make()
    _serve(served, man, blob, _sign(Ed25519PrivateKey.generate(), man))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and "chữ ký" in r["reason"]


def test_garbage_signature_rejected(env):
    _, served, dest, _ = env
    man, blob = _make()
    _serve(served, man, blob, b"not-base64!!")
    assert updater.check_and_update(URL, dest)["updated"] is False


def test_missing_sig_refused_when_required(env):
    _, served, dest, _ = env
    man, blob = _make()
    _serve(served, man, blob)
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and ".sig" in r["reason"]


def test_missing_sig_allowed_when_not_required(env, caplog):
    _, served, dest, settings = env
    settings.kb_require_signature = False
    man, blob = _make()
    _serve(served, man, blob)
    with caplog.at_level("WARNING"):
        r = updater.check_and_update(URL, dest)
    assert r["updated"] is True
    assert "không có chữ ký" in caplog.text


def test_invalid_sig_rejected_even_when_not_required(env):
    _, served, dest, settings = env
    settings.kb_require_signature = False
    man, blob = _make()
    _serve(served, man, blob, _sign(Ed25519PrivateKey.generate(), man))
    assert updater.check_and_update(URL, dest)["updated"] is False


def test_key_rotation_any_key_accepted(env, monkeypatch):
    key, served, dest, _ = env
    new = Ed25519PrivateKey.generate()
    monkeypatch.setattr(updater, "KB_PUBLIC_KEYS", [_pub(key), _pub(new)])
    man, blob = _make()
    _serve(served, man, blob, _sign(new, man))
    assert updater.check_and_update(URL, dest)["updated"] is True


def test_replay_of_older_signed_bundle_rejected(env):
    key, served, dest, _ = env
    new_m, new_b = _make(_today())
    _serve(served, new_m, new_b, _sign(key, new_m))
    assert updater.check_and_update(URL, dest)["updated"] is True
    # kẻ tấn công replay bundle cũ (chữ ký hợp lệ) — kể cả force
    old_m, old_b = _make(_today(-30))
    _serve(served, old_m, old_b, _sign(key, old_m))
    for force in (False, True):
        r = updater.check_and_update(URL, dest, force=force)
        assert r["updated"] is False
    assert get_meta(dest)["version"] is not None
    assert "rollback" in r["reason"] or "hạ cấp" in r["reason"]


def test_embedded_public_key_is_valid_ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    importlib_keys = __import__("importlib").reload(updater).KB_PUBLIC_KEYS
    assert importlib_keys
    for k in importlib_keys:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(k))


# ── review fixes (PR #44 verify) ──
@pytest.mark.parametrize("bad", [503, 403, 429, 500])
def test_sig_non_404_error_fails_closed_even_when_not_required(env, bad):
    _, served, dest, settings = env
    settings.kb_require_signature = False
    man, blob = _make()
    _serve(served, man, blob)
    served[URL + ".sig"] = bad
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and not os.path.exists(dest)


def test_sig_timeout_fails_closed(env):
    import httpx
    _, served, dest, settings = env
    settings.kb_require_signature = False
    man, blob = _make()
    _serve(served, man, blob)
    served[URL + ".sig"] = httpx.ReadTimeout("t")
    assert updater.check_and_update(URL, dest)["updated"] is False
    assert not os.path.exists(dest)


def test_unsigned_future_version_cannot_poison_floor(env):
    key, served, dest, settings = env
    settings.kb_require_signature = False
    man, blob = _make(version="9999.01.01")
    _serve(served, man, blob)
    assert updater.check_and_update(URL, dest)["updated"] is False   # version tương lai
    # kể cả bản chưa ký version hợp lệ → rồi bản ký đầu tiên luôn được cài (không bị sàn chưa-ký chặn)
    m1, b1 = _make(version=_today(1))
    _serve(served, m1, b1)
    assert updater.check_and_update(URL, dest)["updated"] is True
    settings.kb_require_signature = True
    m2, b2 = _make(version=_today())          # cũ hơn bản chưa ký local nhưng là bản đã ký đầu tiên
    _serve(served, m2, b2, _sign(key, m2))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is True, r


def test_floor_only_from_verified(env):
    key, served, dest, settings = env
    settings.kb_require_signature = False
    # cài bản chưa ký (hợp lệ)
    m, b = _make(version=_today(1))  # tối đa +2 ngày được phép
    _serve(served, m, b)
    assert updater.check_and_update(URL, dest)["updated"] is True
    assert not os.path.exists(dest + ".sigstate")
    # bản ký version thấp hơn vẫn recovery được
    m2, b2 = _make(version=_today())
    _serve(served, m2, b2, _sign(key, m2))
    assert updater.check_and_update(URL, dest)["updated"] is True
    assert os.path.exists(dest + ".sigstate")


def test_sticky_signature_after_first_signed_install(env):
    key, served, dest, settings = env
    settings.kb_require_signature = False
    m, b = _make(version=_today(-1))
    _serve(served, m, b, _sign(key, m))
    assert updater.check_and_update(URL, dest)["updated"] is True
    # kẻ tấn công gỡ .sig → bị từ chối dù require=false
    m2, b2 = _make(version=_today())
    _serve(served, m2, b2)
    served.pop(URL + ".sig", None)
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and ".sig" in r["reason"]


def test_absurd_future_version_rejected_even_if_signed(env):
    key, served, dest, _ = env
    m, b = _make(version="9999.01.01")
    _serve(served, m, b, _sign(key, m))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and "tương lai" in r["reason"]


def test_same_version_force_replay_of_older_build_rejected(env):
    key, served, dest, _ = env
    new_m, new_b = _make(built_at=_now_iso(0))
    _serve(served, new_m, new_b, _sign(key, new_m))
    assert updater.check_and_update(URL, dest)["updated"] is True
    old_m, old_b = _make(built_at=_now_iso(1))   # cùng version, build cũ hơn
    _serve(served, old_m, old_b, _sign(key, old_m))
    r = updater.check_and_update(URL, dest, force=True)
    assert r["updated"] is False and "replay" in r["reason"]


def test_stale_signed_manifest_flagged(env, caplog):
    key, served, dest, _ = env
    m, b = _make(built_at=_now_iso(30))
    _serve(served, m, b, _sign(key, m))
    with caplog.at_level("WARNING"):
        r = updater.check_and_update(URL, dest)
    assert r["updated"] is True and r["stale"] is True
    assert "freeze" in caplog.text
    r2 = updater.check_and_update(URL, dest)
    assert r2["reason"] == "đã mới nhất" and r2["stale"] is True


def test_fresh_signed_manifest_not_stale(env):
    key, served, dest, _ = env
    m, b = _make()
    _serve(served, m, b, _sign(key, m))
    assert updater.check_and_update(URL, dest)["stale"] is False


def test_oversized_manifest_rejected(env, monkeypatch):
    key, served, dest, _ = env
    m, b = _make()
    big = m + b" " * (updater.MAX_MANIFEST_BYTES + 1)
    _serve(served, big, b, _sign(key, big))
    assert updater.check_and_update(URL, dest)["updated"] is False


def test_oversized_snapshot_download_rejected(env, monkeypatch):
    key, served, dest, _ = env
    monkeypatch.setattr(updater, "MAX_SNAPSHOT_BYTES", 100)
    m, b = _make()
    _serve(served, m, b, _sign(key, m))
    assert updater.check_and_update(URL, dest)["updated"] is False


def test_gzip_bomb_rejected_by_import_file(tmp_path):
    bomb = tmp_path / "bomb.gz"
    with gzip.open(bomb, "wb") as f:
        f.write(b"\0" * (8 << 20))
    with pytest.raises(ValueError, match="giới hạn"):
        updater.import_file(str(bomb), str(tmp_path / "kb.sqlite"), max_uncompressed=1 << 20)
    assert not (tmp_path / "kb.sqlite").exists()


def test_gzip_bomb_via_signed_update_rejected(env, monkeypatch):
    key, served, dest, _ = env
    monkeypatch.setattr(updater, "_max_uncompressed", lambda: 1 << 20)
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(b"\0" * (8 << 20))
    m, b = _make(raw_blob=buf.getvalue())
    _serve(served, m, b, _sign(key, m))
    r = updater.check_and_update(URL, dest)
    assert r["updated"] is False and "giới hạn" in r["reason"]
    assert not os.path.exists(dest)
