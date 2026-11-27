import os
def f(cmd):
    # ruleid: os-system-injection
    os.system(cmd)
    # ruleid: os-system-injection
    os.system("ls " + cmd)
    # ok: os-system-injection
    os.system("clear")
