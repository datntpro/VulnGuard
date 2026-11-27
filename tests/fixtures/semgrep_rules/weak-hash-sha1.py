import hashlib
def f(data):
    # ruleid: weak-hash-sha1
    hashlib.sha1(data)
    # ruleid: weak-hash-sha1
    hashlib.new("sha1")
    # ok: weak-hash-sha1
    hashlib.sha1(data, usedforsecurity=False)
    # ok: weak-hash-sha1
    hashlib.new("sha256", data)
