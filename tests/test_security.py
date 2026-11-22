from api.security import (create_token, decode_token, decrypt_secret, encrypt_secret,
                          hash_password, verify_password)


def test_password_hash_roundtrip():
    h = hash_password("S3cret!longpass")
    assert verify_password("S3cret!longpass", h)
    assert not verify_password("wrong", h)


def test_secret_encryption_roundtrip():
    tok = encrypt_secret("sk-ant-very-secret")
    assert tok != "sk-ant-very-secret"
    assert decrypt_secret(tok) == "sk-ant-very-secret"


def test_jwt_roundtrip():
    t = create_token("u1", "ADMIN", 0)
    p = decode_token(t)
    assert p and p["sub"] == "u1" and p["role"] == "ADMIN"
    assert decode_token("garbage") is None
