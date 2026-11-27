def f(base, name):
    # ruleid: open-with-user-input
    open(base + name)
    # ruleid: open-with-user-input
    open(f"/srv/files/{name}", "rb")
    # ok: open-with-user-input
    open("/etc/hosts")
    # ok: open-with-user-input
    open("/srv/" + "static.txt")
