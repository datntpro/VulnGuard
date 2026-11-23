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
        # P0.3: bắt đổi mật khẩu ở lần đăng nhập đầu
        db.add(User(email=email, name="Administrator",
                    password_hash=hash_password(password), role=UserRole.ADMIN,
                    must_change_password=True))
        db.commit()
    finally:
        db.close()

    # P0.3: KHÔNG in mật khẩu ra màn hình/log — chỉ ghi file chmod 600 (gitignored)
    cred_path = os.path.join(settings.storage_dir, "admin_credentials.txt")
    saved = False
    try:
        os.makedirs(os.path.dirname(cred_path), exist_ok=True)
        fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"VulnGuard ADMIN\nEmail: {email}\nMật khẩu: {password}\n"
                    f"(BẮT BUỘC đổi mật khẩu khi đăng nhập lần đầu, rồi XOÁ file này.)\n")
        saved = True
    except Exception:
        saved = False

    bar = "═" * 52
    print(f"\n{bar}")
    print("  🔐 TÀI KHOẢN ADMIN ĐÃ TẠO")
    print(f"  Email: {email}")
    if saved:
        print(f"  Mật khẩu đã lưu tại: {cred_path} (chmod 600)")
        print("  → Mở file để lấy mật khẩu, đăng nhập, ĐỔI mật khẩu, rồi XOÁ file.")
    else:
        print("  ⚠️  Không ghi được file credential. Đặt ADMIN_PASSWORD rồi chạy lại,")
        print("     hoặc tạo ADMIN qua trang đăng nhập lần đầu.")
    print("  (Vì an toàn, mật khẩu KHÔNG được in ra màn hình/log.)")
    print(bar + "\n")


if __name__ == "__main__":
    main()
