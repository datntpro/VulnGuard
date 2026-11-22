"""
Tạo tài khoản ADMIN đầu tiên với mật khẩu sinh ngẫu nhiên (gọi từ setup.sh).
- Nếu đã có user: bỏ qua (không ghi đè).
- In credential ra màn hình + ghi storage/admin_credentials.txt (chmod 600) để không mất.
Dùng: python -m scripts.bootstrap_admin [email]
"""
import os
import secrets
import string
import sys

import api.main  # tạo bảng
from api.database import SessionLocal
from api.auth_models import User, UserRole
from api.security import hash_password
from api.config import settings


def gen_password(n: int = 20) -> str:
    # Mạnh nhưng tránh ký tự dễ nhầm; đảm bảo có đủ loại.
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#%^*-_=+" for c in pw)):
            return pw


def main():
    email = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ADMIN_EMAIL") or "admin@vulnguard.local").strip().lower()
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            print("ℹ️  Đã có tài khoản — bỏ qua tạo ADMIN. (Đổi mật khẩu trong Settings → Người dùng.)")
            return
        password = os.environ.get("ADMIN_PASSWORD") or gen_password()
        db.add(User(email=email, name="Administrator",
                    password_hash=hash_password(password), role=UserRole.ADMIN))
        db.commit()
    finally:
        db.close()

    # Ghi file chmod 600 (gitignored)
    cred_path = os.path.join(settings.storage_dir, "admin_credentials.txt")
    try:
        os.makedirs(os.path.dirname(cred_path), exist_ok=True)
        fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"VulnGuard ADMIN\nEmail: {email}\nMật khẩu: {password}\n"
                    f"(Đổi mật khẩu sau khi đăng nhập, rồi xoá file này.)\n")
    except Exception:
        cred_path = None

    bar = "═" * 52
    print(f"\n{bar}")
    print("  🔐 TÀI KHOẢN ADMIN ĐÃ TẠO — LƯU LẠI NGAY")
    print(f"  Email:    {email}")
    print(f"  Mật khẩu: {password}")
    if cred_path:
        print(f"  (Đã lưu {cred_path} — chmod 600; đổi mật khẩu rồi xoá file.)")
    print(bar + "\n")


if __name__ == "__main__":
    main()
