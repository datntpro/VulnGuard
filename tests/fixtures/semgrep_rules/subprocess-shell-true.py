import subprocess
def f(cmd):
    # ruleid: subprocess-shell-true
    subprocess.run(cmd, shell=True)
    # ruleid: subprocess-shell-true
    subprocess.call(cmd, shell=True)
    # ruleid: subprocess-shell-true
    subprocess.Popen(cmd, cwd="/", shell=True)
    # ruleid: subprocess-shell-true
    subprocess.check_output(cmd, shell=True, text=True)
    # ruleid: subprocess-shell-true
    subprocess.check_call(cmd, shell=True)
    # ok: subprocess-shell-true
    subprocess.run(["ls", cmd])
    # ok: subprocess-shell-true
    subprocess.run(cmd, shell=False)
