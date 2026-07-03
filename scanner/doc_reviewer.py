"""
Document Reviewer — dùng Ollama (AI local) để đánh giá 1 tài liệu phát triển hệ thống
(SRS/FRS/BRD, HLD/LLD, đặc tả API/DB schema) theo checklist an toàn thông tin
(scanner/doc_checklist.py, dựa trên OWASP ASVS).

Thiết kế giống scanner/ai_analyzer.py (cùng Ollama endpoint, cùng cấu hình) nhưng
tách riêng vì input là toàn văn tài liệu (dài) thay vì 1 vulnerability record.

Chiến lược: tài liệu được cắt còn 1 đoạn vừa context window của model local, checklist
được chia thành các batch nhỏ (mặc định 5 tiêu chí/lần gọi) để AI trả JSON gọn, giảm
rủi ro bị cắt response hoặc lệch format.
"""
import httpx
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Số ký tự tài liệu đưa vào mỗi prompt — model local (llama3.2 8k ctx mặc định Ollama)
# nên giữ vừa phải để AI không bị "quên" phần đầu/cuối tài liệu.
DOC_EXCERPT_CHARS = 9000

# Số tiêu chí đánh giá mỗi lần gọi Ollama — giữ nhỏ để response JSON không bị cắt cụt.
# Giảm từ 5 → 3: evidence model viết khá dài, batch 5 dễ vượt num_predict trước khi
# đóng JSON array (gây lỗi "AI trả về dữ liệu không đúng format JSON").
BATCH_SIZE = 3

# Context window yêu cầu Ollama cấp cho request này — set rõ vì default Modelfile
# của nhiều model chỉ 2048 token, không đủ chứa DOC_EXCERPT_CHARS (~9000 ký tự văn
# bản tiếng Việt ≈ 3000-4500 token) + prompt + chỗ để sinh output → model trả response rỗng.
OLLAMA_NUM_CTX = 8192

PROMPT_TEMPLATE = """Bạn là chuyên gia bảo mật ứng dụng (AppSec) đang review tài liệu phát triển hệ thống
để kiểm tra xem tài liệu đã đề cập/đáp ứng các yêu cầu an toàn thông tin sau chưa.

## Loại tài liệu: {doc_type_label}

## Nội dung tài liệu (có thể đã bị cắt nếu quá dài):
\"\"\"
{doc_excerpt}
\"\"\"

## Các tiêu chí cần đánh giá:
{criteria_list}

## Yêu cầu:
Với MỖI tiêu chí, đánh giá tài liệu đã đáp ứng đến đâu và trả lời bằng tiếng Việt.
CHỈ trả về JSON array (không thêm text ngoài JSON, không markdown wrapper), theo format:
[
  {{
    "criteria_id": "ASVS-2.1",
    "status": "MET",
    "evidence": "Trích dẫn/diễn giải NGẮN phần tài liệu liên quan, hoặc lý do nếu NOT_MET",
    "recommendation": "Gợi ý cụ thể cần bổ sung/sửa trong tài liệu (để trống nếu MET hoàn toàn)"
  }}
]

Chú ý:
- status chỉ nhận 1 trong 4 giá trị: "MET" (đã đáp ứng đầy đủ), "PARTIAL" (có đề cập nhưng chưa đầy đủ/rõ ràng),
  "NOT_MET" (không đề cập), "NOT_APPLICABLE" (tiêu chí không liên quan đến phạm vi tài liệu này)
- evidence phải dựa trên nội dung THỰC TẾ có trong tài liệu, không suy diễn
- Nếu tài liệu không đề cập gì tới tiêu chí, status phải là NOT_MET, evidence ghi rõ "Tài liệu không đề cập"
- BẮT BUỘC viết evidence và recommendation NGẮN GỌN — tối đa 1-2 câu, dưới 150 ký tự mỗi trường.
  KHÔNG viết đoạn văn dài, không trích dẫn dài dòng.
- Trả đủ {n_criteria} object trong array, đúng thứ tự criteria_id đã cho
"""


class DocReviewer:
    def __init__(self):
        from api.config import settings as _settings
        self.ollama_url = _settings.ollama_url
        self.timeout = _settings.ollama_timeout
        self.model = self._get_active_model()

    def _get_active_model(self) -> str:
        try:
            from api.routes.ollama import get_active_model
            return get_active_model()
        except Exception:
            pass
        return os.environ.get("OLLAMA_MODEL", "llama3.2")

    async def review(self, doc_text: str, doc_type_label: str, checklist: list) -> list[dict[str, Any]]:
        """checklist: list of (criteria_id, category, criteria_text).
        Trả về list finding dict: {criteria_id, category, criteria_text, status, evidence, recommendation}
        """
        self.model = self._get_active_model()
        excerpt = doc_text[:DOC_EXCERPT_CHARS]
        truncated = len(doc_text) > DOC_EXCERPT_CHARS

        by_id = {c[0]: (c[1], c[2]) for c in checklist}
        findings: list[dict[str, Any]] = []

        for i in range(0, len(checklist), BATCH_SIZE):
            batch = checklist[i:i + BATCH_SIZE]
            fail_reason = None
            try:
                results = await self._review_batch(excerpt, doc_type_label, batch, truncated)
                if not results:
                    fail_reason = "AI trả về dữ liệu không đúng format JSON mong đợi (xem log server để biết raw response)"
            except httpx.ConnectError as e:
                fail_reason = f"Không kết nối được Ollama ({self.ollama_url}) — kiểm tra `ollama serve` đang chạy trên host"
                logger.error(f"Doc review batch failed — connect error: {e}")
                results = {}
            except httpx.TimeoutException as e:
                fail_reason = f"Ollama trả lời quá lâu (timeout {self.timeout}s) — thử model nhẹ hơn hoặc tăng OLLAMA_TIMEOUT"
                logger.error(f"Doc review batch failed — timeout: {e}")
                results = {}
            except Exception as e:
                fail_reason = f"Lỗi không xác định khi gọi AI: {e}"
                logger.error(f"Doc review batch failed: {e}", exc_info=True)
                results = {}

            for criteria_id, category, criteria_text in batch:
                r = results.get(criteria_id, {})
                status = r.get("status", "NOT_MET")
                if status not in ("MET", "PARTIAL", "NOT_MET", "NOT_APPLICABLE"):
                    status = "NOT_MET"
                if r:
                    evidence = r.get("evidence") or ""
                elif fail_reason:
                    evidence = fail_reason
                else:
                    evidence = "AI không trả về kết quả cho tiêu chí này — cần review thủ công"
                findings.append({
                    "criteria_id": criteria_id,
                    "category": category,
                    "criteria_text": criteria_text,
                    "status": status,
                    "evidence": evidence,
                    "recommendation": r.get("recommendation") or "",
                })

        return findings

    async def _review_batch(self, excerpt: str, doc_type_label: str, batch: list, truncated: bool) -> dict:
        criteria_list = "\n".join(
            f"- [{cid}] {text}" for cid, _cat, text in batch
        )
        note = "\n(Lưu ý: tài liệu dài hơn đoạn trích ở trên, đã bị cắt — nếu nội dung liên quan có thể nằm ngoài phần này, hãy đánh giá PARTIAL thay vì NOT_MET khi không chắc chắn.)" if truncated else ""

        prompt = PROMPT_TEMPLATE.format(
            doc_type_label=doc_type_label,
            doc_excerpt=excerpt + note,
            criteria_list=criteria_list,
            n_criteria=len(batch),
        )
        response_text = await self._call_ollama(prompt)
        return self._parse_batch_response(response_text)

    async def _call_ollama(self, prompt: str) -> str:
        timeout = httpx.Timeout(connect=10.0, read=float(self.timeout), write=10.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            response = await client.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "num_predict": 1536,
                        "num_ctx": OLLAMA_NUM_CTX,
                    },
                },
            )
            response.raise_for_status()
            return response.json().get("response", "")

    def _parse_batch_response(self, text: str) -> dict:
        """Trả về dict criteria_id -> {status, evidence, recommendation}."""
        raw = (text or "").strip()
        start = raw.find("[")
        end = raw.rfind("]") + 1
        items = None

        if start >= 0 and end > start:
            try:
                items = json.loads(raw[start:end])
            except json.JSONDecodeError:
                items = None

        if items is None:
            # Fallback: model có thể bọc array trong object, ví dụ {"results": [...]}
            obj_start = raw.find("{")
            obj_end = raw.rfind("}") + 1
            if obj_start >= 0 and obj_end > obj_start:
                try:
                    obj = json.loads(raw[obj_start:obj_end])
                    if isinstance(obj, dict):
                        for v in obj.values():
                            if isinstance(v, list):
                                items = v
                                break
                except json.JSONDecodeError:
                    pass

        if items is None:
            # Fallback cuối: response bị cắt cụt giữa array (hết num_predict trước khi
            # đóng "]") — vớt từng object hoàn chỉnh đã sinh ra được thay vì bỏ hết.
            # Giả định object không lồng nhau (đúng với format prompt yêu cầu).
            import re
            items = []
            for m in re.finditer(r"\{[^{}]*\}", raw):
                try:
                    obj = json.loads(m.group(0))
                    if isinstance(obj, dict):
                        items.append(obj)
                except json.JSONDecodeError:
                    continue
            if not items:
                logger.warning(
                    "Doc reviewer: AI không trả JSON hợp lệ — raw response (500 ký tự đầu): %r",
                    raw[:500],
                )
                return {}
            logger.warning(
                "Doc reviewer: response bị cắt cụt — vớt được %d/%d object từ JSON không hoàn chỉnh",
                len(items), BATCH_SIZE,
            )

        out = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            cid = item.get("criteria_id")
            if cid:
                out[cid] = item
        return out

    async def check_ollama_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                r = await client.get(f"{self.ollama_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False
