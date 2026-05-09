from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

from api.config import settings

# Đảm bảo thư mục DB tồn tại (chỉ tạo nếu là absolute path hợp lệ)
try:
    db_path = settings.database_url.replace("sqlite:////", "/").replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and os.path.isabs(db_path):
        os.makedirs(db_dir, exist_ok=True)
except Exception:
    pass

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=(settings.app_env == "development"),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

