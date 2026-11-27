import hashlib
def f(data):
    # ruleid: weak-hash-md5
    hashlib.md5(data)
    # ruleid: weak-hash-md5
    hashlib.new("md5", data)
    # ok: weak-hash-md5
    hashlib.md5(data, usedforsecurity=False)
    # ok: weak-hash-md5
    hashlib.sha256(data)
