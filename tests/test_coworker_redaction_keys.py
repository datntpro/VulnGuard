"""[W3-15] Co-work cloud egress: khoá riêng tư (PEM/base64/PGP/PuTTY) phải được che kể cả khi nội dung bị cắt dài.
Khoá sinh lúc chạy test; không có khoá thật nào được commit."""
import asyncio
import base64
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from api.routes import coworker_agent as ca
from api.services import coworker_cloud as cc


def _pem(kind: str) -> str:
    if kind == "rsa":
        k = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif kind == "ec":
        k = ec.generate_private_key(ec.SECP256R1())
    else:
        k = ed25519.Ed25519PrivateKey.generate()
    return k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()


def _body(pem: str) -> str:
    return "".join(l for l in pem.splitlines() if not l.startswith("-----"))


def _no_fragment(out: str, body: str, w: int = 16) -> bool:
    return all(body[i:i + w] not in out for i in range(0, len(body) - w, 4))


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _synthetic_pgp() -> str:
    rnd = base64.b64encode(os.urandom(2400)).decode()
    lines = [rnd[i:i + 64] for i in range(0, len(rnd), 64)]
    return ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + "\n".join(lines) + "\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----\n")


def _synthetic_ppk() -> str:
    pub = base64.b64encode(os.urandom(300)).decode()
    priv = base64.b64encode(os.urandom(900)).decode()
    return ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: synthetic\nPublic-Lines: 2\n"
            + "\n".join(pub[i:i + 64] for i in range(0, len(pub), 64))
            + "\nPrivate-Lines: 4\n" + "\n".join(priv[i:i + 64] for i in range(0, len(priv), 64))
            + "\nPrivate-MAC: " + os.urandom(16).hex() + "\n")


KINDS = ["rsa", "ec", "ed25519"]


def _wrap(text: str, cap: int = ca.MAX_FILE_CHARS + 500) -> str:
    return cc.wrap_observation(text, cap=cap)[0]


@pytest.mark.parametrize("kind", KINDS)
def test_plain_pem(kind):
    pem = _pem(kind)
    out = _wrap("Nội dung 'x':\n" + pem)
    assert _no_fragment(out, _body(pem))
    assert cc.redact_egress(pem).count("BEGIN") == 0


@pytest.mark.parametrize("kind", KINDS)
def test_pem_crossing_the_old_cut(kind):
    pem = _pem(kind)
    filler = "# filler line for padding of a configuration file\n"
    head = (filler * 400)[:11_990]
    text = head + pem + (filler * 400)
    assert len(text) > 20_000 and text.index("-----BEGIN") == 11_990
    out = _wrap(text)
    assert _no_fragment(out, _body(pem))
    # chuỗi giao cho model cũng bị cắt đúng cap sau khi che
    assert len(out) < ca.MAX_FILE_CHARS + 1000


@pytest.mark.parametrize("kind", KINDS)
def test_unterminated_pem_is_redacted(kind):
    pem = _pem(kind)
    cut = pem[:len(pem) // 2]            # không có dòng END
    assert _no_fragment(_wrap("a\n" + cut), _body(cut))


@pytest.mark.parametrize("kind", KINDS)
def test_kubeconfig_client_key_data(kind):
    pem = _pem(kind)
    kc = ("apiVersion: v1\nusers:\n- name: admin\n  user:\n    client-certificate-data: " + _b64("CERT") * 3 +
          "\n    client-key-data: " + _b64(pem) + "\n")
    assert _no_fragment(_wrap(kc), _b64(pem))
    assert _no_fragment(cc.redact_egress(kc), _b64(pem))


@pytest.mark.parametrize("kind", KINDS)
def test_helm_tls_key_and_bare_base64_line(kind):
    pem = _pem(kind)
    b = _b64(pem)
    assert _no_fragment(_wrap("tls:\n  crt: abc\n  tls.key: " + b + "\n"), b)
    # một dòng base64 dài, không có khoá/dấu `=`/`:`
    assert _no_fragment(_wrap("noise\n" + b + "\nmore"), b)
    big = _b64(pem + pem[:2000] * 2)
    assert len(big) > 5000 and _no_fragment(_wrap(big, cap=20000), big)


def test_pgp_block():
    pgp = _synthetic_pgp()
    assert _no_fragment(_wrap("x\n" + pgp), _body(pgp).replace("=abcd", ""))
    cut = pgp[:1500]
    assert _no_fragment(_wrap(cut), _body(cut))


def test_putty_block():
    ppk = _synthetic_ppk()
    out = _wrap("cfg\n" + ppk + "after")
    assert _no_fragment(out, _body(ppk.split("Private-Lines:")[1].split("Private-MAC")[0].replace("\n", "")[2:]))
    assert "after" in out


def test_redact_messages_transcript_holds_no_fragment():
    pem = _pem("ec")
    msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "x\n" + pem[:700]}]},
            {"role": "user", "content": "client-key-data: " + _b64(pem)}]
    out = repr(cc.redact_messages(msgs))
    assert _no_fragment(out, _body(pem)) and _no_fragment(out, _b64(pem))


@pytest.mark.parametrize("path", ["k3s.yaml", "deploy/admin.conf", "x/release.asc", "keys/y.ppk", "a/b.gpg",
                                  "c/d.ovpn", "secring.gpg", "home/me.kubeconfig"])
def test_new_sensitive_basenames(path):
    assert cc.is_sensitive_path(path)


def test_normal_files_not_sensitive():
    for p in ("README.md", "src/app.py", "docs/key-concepts.md", "ascii.txt"):
        assert not cc.is_sensitive_path(p)


def test_local_route_cut_is_unchanged(monkeypatch):
    content = "".join(f"line {i} of a long file\n" for i in range(2000))
    assert len(content) > 20_000

    async def fake_host(method, path, **kw):
        return {"content": content, "binary": False}
    monkeypatch.setattr(ca, "_host_request", fake_host)
    local = asyncio.run(ca._run_readonly("f", "read_file", {"path": "a.txt"}))
    expect = "Nội dung 'a.txt':\n" + content[:ca.MAX_FILE_CHARS] + "\n…[đã cắt bớt do file dài]…"
    assert local == expect
    raw = asyncio.run(ca._run_readonly("f", "read_file", {"path": "a.txt"}, raw=True))
    assert len(raw) > len(local) and content[:ca.MAX_FILE_CHARS + 5000] in raw


def test_wrap_observation_perf_200kb():
    chunk = "def f(x):\n    return x + 1  # comment with some words and 12345\nname = 'value'\n"
    text = (chunk * 3000)[:200_000]
    t = time.time()
    cc.wrap_observation(text, cap=200_000)
    assert time.time() - t < 1.0
