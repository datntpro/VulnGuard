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


# ── SonarQube (server URL + token mã hoá) ──
def sonarqube_url() -> str:
    from api.config import settings
    return ((load().get("sonarqube_url") or "").strip() or settings.sonarqube_url or "").rstrip("/")


def sonarqube_token() -> str:
    from api.security import decrypt_secret
    from api.config import settings
    enc = load().get("sonarqube_token_enc")
    return (decrypt_secret(enc) if enc else None) or settings.sonarqube_token or ""


def sonarqube_is_custom() -> bool:
    d = load()
    return bool((d.get("sonarqube_url") or "").strip() or d.get("sonarqube_token_enc"))


def set_sonarqube(url: Optional[str] = None, token: Optional[str] = None,
                  clear_token: bool = False) -> Dict[str, Any]:
    from api.security import encrypt_secret
    upd: Dict[str, Any] = {}
    if url is not None:
        upd["sonarqube_url"] = url.strip().rstrip("/") or None
    if clear_token:
        upd["sonarqube_token_enc"] = None
    elif token:
        upd["sonarqube_token_enc"] = encrypt_secret(token.strip())
    return save(upd)


# ── SMTP (gửi report tự động cho owner) ──
def smtp_config() -> Dict[str, Any]:
    from api.security import decrypt_secret
    d = load()
    return {
        "host": d.get("smtp_host") or "",
        "port": int(d.get("smtp_port") or 587),
        "username": d.get("smtp_user") or "",
        "password": decrypt_secret(d.get("smtp_pass_enc")) if d.get("smtp_pass_enc") else "",
        "from_addr": d.get("smtp_from") or (d.get("smtp_user") or ""),
        "use_tls": bool(d.get("smtp_tls", True)),
    }


def smtp_is_configured() -> bool:
    c = smtp_config()
    return bool(c["host"] and c["from_addr"])


def set_smtp(host=None, port=None, username=None, password=None, from_addr=None,
             use_tls=None, clear_password=False) -> Dict[str, Any]:
    from api.security import encrypt_secret
    upd: Dict[str, Any] = {}
    if host is not None:
        upd["smtp_host"] = host.strip() or None
    if port is not None:
        upd["smtp_port"] = int(port)
    if username is not None:
        upd["smtp_user"] = username.strip() or None
    if from_addr is not None:
        upd["smtp_from"] = from_addr.strip() or None
    if use_tls is not None:
        upd["smtp_tls"] = bool(use_tls)
    if clear_password:
        upd["smtp_pass_enc"] = None
    elif password:
        upd["smtp_pass_enc"] = encrypt_secret(password.strip())
    return save(upd)
