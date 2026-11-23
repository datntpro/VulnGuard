# Repo mẫu có lỗi ĐÃ BIẾT — dùng cho test hồi quy (1.8). KHÔNG dùng trong production.
import subprocess

DB_PASSWORD = "SuperSecretP@ssw0rd123"   # hardcoded secret (bandit B105)


def run(cmd):
    return subprocess.call(cmd, shell=True)  # shell injection (bandit B602)


def query(user_input):
    sql = "SELECT * FROM users WHERE name = '" + user_input + "'"  # SQLi pattern
    return sql
