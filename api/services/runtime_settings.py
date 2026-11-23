"""
Runtime settings bền vững (ghi file, sống qua restart) cho cấu hình người dùng
chỉnh trong dashboard — tách khỏi .env/biến môi trường.

Hiện dùng cho Ollama: endpoint (local hoặc IP máy khác — KHÔNG bắt buộc Docker)
và model text/vision đang chọn. Trước đây các giá trị này chỉ nằm in-memory nên
mất khi restart; giờ lưu <storage>/runtime_settings.json.
"""
import json
import os
import threading
from typing import Any, Dict, Optional

from api.config import settings

_lock = threading.Lock()


def _path() -> str:
    return os.environ.get("RUNTIME_SETTINGS_FILE") or os.path.join(settings.storage_dir, "runtime_settings.json")


def load() -> Dict[str, Any]:
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save(update: Dict[str, Any]) -> Dict[str, Any]:
    with _lock:
        cur = load()
        for k, v in (update or {}).items():
            if v is None:
                cur.pop(k, None)
            else:
                cur[k] = v
        path = _path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return cur


# ── Ollama ──
def ollama_url() -> str:
    """Endpoint Ollama hiệu lực: override người dùng > env OLLAMA_URL > mặc định."""
    v = (load().get("ollama_url") or "").strip()
    return (v or settings.ollama_url).rstrip("/")


def ollama_url_is_custom() -> bool:
    return bool((load().get("ollama_url") or "").strip())


def ollama_model() -> str:
    return (load().get("ollama_model") or "").strip() or settings.ollama_model


def ollama_vision_model() -> str:
    return (load().get("ollama_vision_model") or "").strip() or settings.ollama_vision_model


def set_ollama(url: Optional[str] = None, model: Optional[str] = None,
               vision_model: Optional[str] = None) -> Dict[str, Any]:
    upd: Dict[str, Any] = {}
    if url is not None:
        upd["ollama_url"] = url.strip().rstrip("/") or None
    if model is not None:
        upd["ollama_model"] = model.strip() or None
    if vision_model is not None:
        upd["ollama_vision_model"] = vision_model.strip() or None
    return save(upd)
