"""
Agent Skills — thư viện "playbook nghiệp vụ" cho Co-work Agent.

Mỗi skill là 1 file Markdown trong api/agent_skills/ có phần frontmatter:

    ---
    id: review-bank-software-doc-nhnn
    name: Review tài liệu phát triển phần mềm ngân hàng (NHNN)
    description: Khi nào nên dùng skill này...
    triggers: từ_khóa_1, từ_khóa_2, ...
    ---
    <nội dung playbook — sẽ được chèn vào system prompt khi skill active>

Agent sẽ tự chọn skill phù hợp theo ngữ cảnh chat (xem routes/coworker_agent.py).
Thêm skill mới = thả 1 file .md vào thư mục, không cần sửa code.
"""
import logging
import os
from functools import lru_cache
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent_skills")


def _parse_skill(path: str) -> Optional[Dict]:
    """Đọc 1 file skill .md, tách frontmatter + body."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        logger.error(f"Không đọc được skill {path}: {e}")
        return None

    meta: Dict[str, str] = {}
    body = raw
    if raw.lstrip().startswith("---"):
        rest = raw.lstrip()[3:]
        end = rest.find("\n---")
        if end != -1:
            front = rest[:end]
            body = rest[end + 4:].lstrip("\n")
            for line in front.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip().lower()] = v.strip()

    skill_id = meta.get("id") or os.path.splitext(os.path.basename(path))[0]
    triggers = [t.strip().lower() for t in meta.get("triggers", "").split(",") if t.strip()]
    return {
        "id": skill_id,
        "name": meta.get("name", skill_id),
        "description": meta.get("description", ""),
        "triggers": triggers,
        "body": body.strip(),
    }


@lru_cache(maxsize=1)
def _load_all_cached() -> tuple:
    skills = []
    if os.path.isdir(SKILLS_DIR):
        for fname in sorted(os.listdir(SKILLS_DIR)):
            if fname.endswith(".md"):
                s = _parse_skill(os.path.join(SKILLS_DIR, fname))
                if s:
                    skills.append(s)
    return tuple(skills)


def list_skills(include_body: bool = False) -> List[Dict]:
    """Danh sách skill. Mặc định bỏ body cho gọn (UI chỉ cần id/name/description)."""
    out = []
    for s in _load_all_cached():
        item = {"id": s["id"], "name": s["name"], "description": s["description"], "triggers": s["triggers"]}
        if include_body:
            item["body"] = s["body"]
        out.append(item)
    return out


def get_skill(skill_id: str) -> Optional[Dict]:
    for s in _load_all_cached():
        if s["id"] == skill_id:
            return dict(s)
    return None


def keyword_match(text: str) -> Optional[str]:
    """Fallback chọn skill bằng từ khóa trigger khi LLM router không chắc."""
    text_l = (text or "").lower()
    best_id, best_score = None, 0
    for s in _load_all_cached():
        score = sum(1 for t in s["triggers"] if t and t in text_l)
        if score > best_score:
            best_id, best_score = s["id"], score
    return best_id if best_score > 0 else None


def reload_skills() -> int:
    """Xóa cache để nạp lại skill mới thêm (gọi khi cần hot-reload)."""
    _load_all_cached.cache_clear()
    return len(_load_all_cached())
