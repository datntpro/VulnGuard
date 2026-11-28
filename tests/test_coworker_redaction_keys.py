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
    big = base64.b64encode(os.urandom(6000)).decode()
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


def _run(coro):
    loop = asyncio.new_event_loop()       # không dùng asyncio.run: nó xoá event loop hiện tại của các test khác
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_local_route_cut_is_unchanged(monkeypatch):
    content = "".join(f"line {i} of a long file\n" for i in range(2000))
    assert len(content) > 20_000

    async def fake_host(method, path, **kw):
        return {"content": content, "binary": False}
    monkeypatch.setattr(ca, "_host_request", fake_host)
    local = _run(ca._run_readonly("f", "read_file", {"path": "a.txt"}))
    expect = "Nội dung 'a.txt':\n" + content[:ca.MAX_FILE_CHARS] + "\n…[đã cắt bớt do file dài]…"
    assert local == expect
    raw = _run(ca._run_readonly("f", "read_file", {"path": "a.txt"}, raw=True))
    assert len(raw) > len(local) and content[:ca.MAX_FILE_CHARS + 5000] in raw


def test_wrap_observation_perf_200kb():
    chunk = "def f(x):\n    return x + 1  # comment with some words and 12345\nname = 'value'\n"
    text = (chunk * 3000)[:200_000]
    t = time.time()
    cc.wrap_observation(text, cap=200_000)
    assert time.time() - t < 1.0


# ── [W3-15 follow-up] tuyến tính + dạng mã hoá còn lại ───────────────────────────────────────────
def _adversarial_inputs():
    n = 200_000
    hdr = "-----BEGIN PRIVATE KEY-----"
    return {
        "headers_lines": (hdr + "\n") * (n // (len(hdr) + 1)),
        "headers_inline": (hdr + " x") * (n // (len(hdr) + 2)),
        "putty_nonl": "PuTTY-User-Key-File-3:" * (n // 22),
        "putty_lines": "PuTTY-User-Key-File-3: a\n" * (n // 25),
        "b64_prefix": "LS0tLS1CRUdJT\n" * (n // 14),
        "end_only": ("-----END PRIVATE KEY-----\n") * (n // 26),
        "mixed": ("-----BEGIN RSA PRIVATE KEY-----\nPuTTY-User-Key-File-2: x\nLS0tLS1CRUdJT\n") * (n // 70),
    }


@pytest.mark.parametrize("name", list(_adversarial_inputs()))
def test_adversarial_200k_is_fast(name):
    text = _adversarial_inputs()[name]
    assert 150_000 <= len(text) <= 200_000
    t = time.time()
    cc.wrap_observation(text, cap=200_000)
    assert time.time() - t < 3.0, name       # tuyến tính: ~ms; ngưỡng rộng cho runner chậm (trước đây: hàng trăm giây)


def test_fail_closed_when_over_budget(monkeypatch):
    import time as _t

    def slow(obs, *, cap):
        _t.sleep(1.0)
        return "LEAK", [], []
    monkeypatch.setattr(cc, "wrap_observation", slow)
    monkeypatch.setattr(cc, "REDACT_BUDGET_S", 0.1)
    text, kinds, hosts = _run(cc.wrap_observation_async("secret-material " * 10, cap=1000))
    assert "LEAK" not in text and "secret-material" not in text and cc.FAIL_CLOSED_TEXT in text


def _esc(s: str) -> str:
    return s.replace("\n", "\\n")


@pytest.mark.parametrize("kind", KINDS)
def test_escaped_newline_forms(kind):
    pem = _pem(kind)
    for frag in (pem[: len(pem) // 2], pem):           # cụt và đủ
        for wrap in ('{"private_key": "%s"}', "key: \"%s\"", "k='%s'"):
            out = _wrap(wrap % _esc(frag))
            assert _no_fragment(out, _body(frag)), (kind, wrap)


def test_escaped_pgp_and_armor_headers():
    pgp = _synthetic_pgp()
    cut = pgp[:1400]
    assert _no_fragment(_wrap('{"k": "%s"}' % _esc(cut)), _body(cut))
    body = base64.b64encode(os.urandom(900)).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    enc = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n"
           + "\n".join(lines[:8]))
    ind = "\n".join("    " + l for l in enc.split("\n"))
    for text in (enc, ind, _esc(enc), "k: |\n" + ind):
        assert _no_fragment(_wrap(text), body[:512]), text[:60]


@pytest.mark.parametrize("kind", KINDS)
def test_line_wrapped_base64_of_pem(kind):
    b = _b64(_pem(kind))
    for width in (64, 76):
        wrapped = "\n".join(b[i:i + width] for i in range(0, len(b), width))
        assert _no_fragment(_wrap(wrapped), b), width
        yaml = "data: |\n" + "\n".join("  " + b[i:i + width] for i in range(0, len(b), width)) + "\nnext: value\n"
        out = _wrap(yaml)
        assert _no_fragment(out, b) and "next: value" in out


def test_base64_of_ppk_and_escaped_ppk():
    ppk = _synthetic_ppk()
    b = _b64(ppk)
    assert _no_fragment(_wrap(b), b)
    wrapped = "\n".join(b[i:i + 76] for i in range(0, len(b), 76))
    assert _no_fragment(_wrap(wrapped), b)
    priv = ppk.split("Private-Lines:")[1].replace("\n", "")[2:600]
    assert _no_fragment(_wrap('{"k": "%s"}' % _esc(ppk)), priv)
    assert _no_fragment(_wrap('{"k": "%s"}' % _esc(ppk[:900])), ppk[100:900].replace("\n", "")[:400])


def test_code_mentioning_headers_is_untouched():
    src = 'HDR = "-----BEGIN PRIVATE KEY-----"\nprint(HDR)\nmore code here\n'
    assert cc.redact_egress(src) == src
