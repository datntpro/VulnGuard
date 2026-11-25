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


class _Resp:
    def __init__(self, content, status=200):
        self.content, self.status_code = content, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")
        return self


def _make(version="2026.11.25"):
    d = tempfile.mkdtemp()
    src = os.path.join(d, "kb.sqlite")
    _seed(src)
    from scanner.knowledge.store import set_meta
    set_meta(src, version=version)
    gz = src + ".gz"
    with open(src, "rb") as fi, gzip.open(gz, "wb") as fo:
        fo.write(fi.read())
    blob = open(gz, "rb").read()
    m = {"version": version, "sha256": hashlib.sha256(blob).hexdigest(), "url": "https://example.test/kb.gz"}
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
        def get(self, url):
            if url not in served:
                return _Resp(b"", 404)
            return _Resp(served[url])

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
    evil = man.replace(b"2026.11.25", b"2099.01.01")
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
    new_m, new_b = _make("2026.11.25")
    _serve(served, new_m, new_b, _sign(key, new_m))
    assert updater.check_and_update(URL, dest)["updated"] is True
    # kẻ tấn công replay bundle cũ (chữ ký hợp lệ) — kể cả force
    old_m, old_b = _make("2026.01.01")
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
