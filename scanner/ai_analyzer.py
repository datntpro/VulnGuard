"""
AI Analyzer — Tích hợp Ollama để phân tích vulnerabilities.
Phân tích: False Positive, Exploitability (public/private), giải thích tiếng Việt, gợi ý fix.
"""
import httpx
import json
import logging
import os
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Fallback messages — dùng để detect và skip khi render report
AI_FALLBACK_MESSAGES = {
    "AI analyzer không thể kết nối. Vui lòng kiểm tra Ollama service.",
    "AI không khả dụng",
    "Cần review thủ công",
    "N/A",
}


def _is_ai_fallback(text: str) -> bool:
    """Kiểm tra xem text có phải là fallback message không (không có giá trị thực)."""
    if not text:
        return True
    stripped = text.strip()
    return stripped in AI_FALLBACK_MESSAGES or stripped.startswith("AI analyzer không thể")


ANALYSIS_PROMPT_TEMPLATE = """Bạn là chuyên gia bảo mật ứng dụng (AppSec). Hãy phân tích vulnerability sau và trả lời bằng tiếng Việt.

## Thông tin Vulnerability:
- **Tool phát hiện**: {tool}
- **Loại scan**: {scan_type}
- **Rule/CVE ID**: {rule_id}
- **Tên lỗ hổng**: {title}
- **Severity**: {severity}
- **File**: {file_path} (dòng {line})
- **Mô tả**: {description}
- **Code liên quan**:
```
{code_snippet}
```
- **CWE**: {cwe}
- **CVE**: {cve}
- **Package**: {package_name} {package_version} (fixed: {fixed_version})

## Yêu cầu phân tích:

Hãy trả lời theo format JSON sau (KHÔNG thêm text ngoài JSON):
{{
  "false_positive_likelihood": "10%",
  "false_positive_reason": "Lý do vắn tắt tại sao đây là/không phải false positive",
  "exploitability_public": "Mô tả ngắn gọn khả năng khai thác khi service public (internet-facing)",
  "exploitability_private": "Mô tả ngắn gọn khả năng khai thác khi service private (internal network)",
  "explanation": "Giải thích lỗ hổng bằng tiếng Việt cho developer hiểu, tại sao nguy hiểm",
  "fix_suggestion": "Gợi ý cụ thể cách fix, kèm code snippet nếu có thể"
}}

Chú ý:
- false_positive_likelihood: % khả năng đây là false positive (0% = chắc chắn thật, 100% = chắc chắn FP)
- Phân tích thực tế, không chung chung
- Nếu là CVE, đề cập đến CVSS score và affected versions nếu biết
- Trả lời chỉ JSON, không markdown wrapper
"""


CRAWL_ANALYSIS_PROMPT_TEMPLATE = """Bạn là chuyên gia bảo mật ứng dụng (AppSec) đang giúp xây dựng baseline WAF
theo positive security model (chỉ cho phép path/method/param đã biết, mặc định deny phần còn lại)
cho domain: {domain_url}

Dưới đây là danh sách endpoint thu được từ crawl (method, path, query/body params, có form hay không):
{endpoint_list}

Hãy trả lời bằng tiếng Việt, CHỈ trả về JSON (không thêm text ngoài JSON, không markdown wrapper), theo format:
{{
  "summary": "Tóm tắt 3-6 câu: site có những khu vực chức năng nào (vd: blog, auth, admin, thanh toán...), đặc điểm nổi bật, rủi ro sơ bộ cần lưu ý khi xây WAF",
  "sensitive_endpoints": [
    {{"path": "/admin/login", "method": "POST", "category": "admin", "reason": "Trang đăng nhập quản trị, cần giới hạn rate-limit và theo dõi brute-force"}}
  ],
  "waf_suggestions": [
    {{"path": "/blog/{{slug}}", "param": "id", "suggested_regex": "^[0-9]+$", "suggested_action": "log", "reason": "Param id chỉ nên là số, nếu thấy ký tự lạ có thể là SQLi/path traversal probe"}}
  ]
}}

Chú ý:
- category trong sensitive_endpoints chỉ dùng 1 trong: auth, admin, payment, upload, api, pii, public, unknown
- suggested_action trong waf_suggestions chỉ là GỢI Ý (log hoặc deny) — không phải rule sẽ tự áp dụng, con người vẫn phải review trước khi enforce deny
- Chỉ liệt kê sensitive_endpoints/waf_suggestions cho path/param THỰC SỰ đáng chú ý, không cần liệt kê hết toàn bộ danh sách
- Nếu danh sách endpoint chủ yếu là trang blog/content tĩnh, không có gì nhạy cảm, có thể để sensitive_endpoints và waf_suggestions là mảng rỗng
"""


class AIAnalyzer:
    def __init__(self):
        # Đọc fresh mỗi lần instantiate — không dùng module-level vars
        # để pick up model thay đổi qua UI (PUT /api/ollama/active-model)
        # Dùng cùng nguồn cấu hình với api/config.py (Settings) để tránh 2 default
        # khác nhau cho cùng 1 biến — Settings đã tự đọc env var OLLAMA_URL/
        # OLLAMA_TIMEOUT nếu có, nên không cần đọc os.environ riêng ở đây nữa.
        from api.config import settings as _settings
        self.ollama_url = _settings.ollama_url
        self.timeout = _settings.ollama_timeout

        # Ưu tiên: active model đã set qua UI > env var > default
        self.model = self._get_active_model()

    def _get_active_model(self) -> str:
        """Lấy active model — ưu tiên từ api/routes/ollama nếu đã import."""
        try:
            from api.routes.ollama import get_active_model
            return get_active_model()
        except Exception:
            pass
        return os.environ.get("OLLAMA_MODEL", "llama3.2")

    async def analyze(self, vuln) -> Dict[str, Any]:
        """Phân tích một vulnerability với Ollama (nhận ORM object)."""
        self.model = self._get_active_model()
        vuln_data = {
            "tool": getattr(vuln, 'tool', ''),
            "scan_type": getattr(vuln, 'scan_type', ''),
            "rule_id": getattr(vuln, 'rule_id', '') or '',
            "title": getattr(vuln, 'title', ''),
            "severity": getattr(vuln, 'severity', '').value if hasattr(getattr(vuln, 'severity', ''), 'value') else str(getattr(vuln, 'severity', '')),
            "file_path": getattr(vuln, 'file_path', '') or '',
            "line_start": getattr(vuln, 'line_start', 0) or 0,
            "description": (getattr(vuln, 'description', '') or '')[:500],
            "code_snippet": (getattr(vuln, 'code_snippet', '') or '')[:300],
            "cwe": getattr(vuln, 'cwe', '') or '',
            "cve": getattr(vuln, 'cve', '') or '',
            "package_name": getattr(vuln, 'package_name', '') or '',
            "package_version": getattr(vuln, 'package_version', '') or '',
            "fixed_version": getattr(vuln, 'fixed_version', '') or '',
        }
        return await self.analyze_raw(vuln_data)

    async def analyze_raw(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Phân tích từ dict (dùng cho concurrent async — tránh SQLAlchemy session issues)."""
        self.model = self._get_active_model()
        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            tool=vuln_data.get("tool", ""),
            scan_type=vuln_data.get("scan_type", ""),
            rule_id=vuln_data.get("rule_id", ""),
            title=vuln_data.get("title", ""),
            severity=vuln_data.get("severity", ""),
            file_path=vuln_data.get("file_path", ""),
            line=vuln_data.get("line_start", 0),
            description=vuln_data.get("description", ""),
            code_snippet=vuln_data.get("code_snippet", ""),
            cwe=vuln_data.get("cwe", ""),
            cve=vuln_data.get("cve", ""),
            package_name=vuln_data.get("package_name", ""),
            package_version=vuln_data.get("package_version", ""),
            fixed_version=vuln_data.get("fixed_version", ""),
        )
        try:
            response_text = await self._call_ollama(prompt)
            return self._parse_response(response_text)
        except Exception as e:
            logger.error(f"AI analysis failed for {vuln_data.get('title', '?')[:50]}: {e}")
            return self._fallback_analysis(str(e))

    async def _call_ollama(self, prompt: str) -> str:
        """Gọi Ollama API với timeout phân tách rõ: connect 10s, read = ollama_timeout."""
        # httpx.Timeout: connect, read, write, pool — phải set read timeout riêng
        # vì LLM generate chậm, chỉ cần connect nhanh
        timeout = httpx.Timeout(
            connect=10.0,       # Kết nối tới Ollama: 10s
            read=float(self.timeout),   # Đọc response (LLM generate): ollama_timeout
            write=10.0,
            pool=5.0,
        )
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
                        "num_predict": 1024,
                    }
                }
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

    def _parse_response(self, text: str) -> Dict[str, Any]:
        """Parse JSON response từ AI."""
        text = text.strip()

        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            json_str = text[start:end]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

        return {
            "false_positive_likelihood": "Không xác định",
            "false_positive_reason": "AI không thể parse kết quả",
            "exploitability_public": text[:200] if text else "Không có dữ liệu",
            "exploitability_private": "Không có dữ liệu",
            "explanation": text[:500] if text else "AI không trả lời được",
            "fix_suggestion": "Vui lòng review thủ công",
        }

    def _fallback_analysis(self, error: str = "") -> Dict[str, Any]:
        reason = f"Lỗi kết nối: {error[:100]}" if error else "AI không khả dụng"
        return {
            "false_positive_likelihood": "N/A",
            "false_positive_reason": reason,
            "exploitability_public": "",
            "exploitability_private": "",
            "explanation": "",           # Để trống → report sẽ không hiển thị AI block
            "fix_suggestion": "",
        }

    async def analyze_crawl(self, domain_url: str, grouped_endpoints: list) -> Dict[str, Any]:
        """Phân tích kết quả crawl 1 domain cho tính năng Sitemap/WAF Baseline.

        grouped_endpoints: list dict đã gom theo path —
            [{"path": "/admin/login", "methods": ["GET","POST"],
              "query_params": [...], "body_params": [...], "has_form": bool}, ...]

        Trả về: {"summary": str, "sensitive_endpoints": [...], "waf_suggestions": [...]}
        Lưu ý an toàn: đây chỉ là GỢI Ý — suggested_action có thể là "deny" nhưng
        không tự áp dụng vào rule thật, luôn cần con người review trước (giống
        disclaimer ở waf_export.py).
        """
        self.model = self._get_active_model()

        truncated_note = ""
        max_paths = 150
        if len(grouped_endpoints) > max_paths:
            truncated_note = (
                f"\n(Lưu ý: domain có {len(grouped_endpoints)} path, danh sách dưới đây "
                f"đã cắt còn {max_paths} path đầu để vừa giới hạn ngữ cảnh AI.)"
            )
            grouped_endpoints = grouped_endpoints[:max_paths]

        lines = []
        for ep in grouped_endpoints:
            params = sorted(set(ep.get("query_params", []) + ep.get("body_params", [])))
            lines.append(
                f"- {'/'.join(ep.get('methods', ['GET']))} {ep.get('path', '/')} "
                f"params=[{', '.join(params) or 'none'}] "
                f"form={'yes' if ep.get('has_form') else 'no'}"
            )
        endpoint_list_text = "\n".join(lines) if lines else "(không có endpoint nào)"

        prompt = CRAWL_ANALYSIS_PROMPT_TEMPLATE.format(
            domain_url=domain_url,
            endpoint_list=endpoint_list_text + truncated_note,
        )
        try:
            response_text = await self._call_ollama_crawl(prompt)
            return self._parse_crawl_response(response_text)
        except Exception as e:
            logger.error(f"AI crawl analysis failed for {domain_url}: {e}")
            return {
                "summary": "",
                "sensitive_endpoints": [],
                "waf_suggestions": [],
                "error": str(e)[:300],
            }

    async def _call_ollama_crawl(self, prompt: str) -> str:
        """Giống _call_ollama nhưng cho phép output dài hơn (list endpoint có thể nhiều)."""
        timeout = httpx.Timeout(connect=10.0, read=float(self.timeout), write=10.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            response = await client.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 2048},
                }
            )
            response.raise_for_status()
            return response.json().get("response", "")

    def _parse_crawl_response(self, text: str) -> Dict[str, Any]:
        text = text.strip()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
                return {
                    "summary": data.get("summary", "") or "",
                    "sensitive_endpoints": data.get("sensitive_endpoints", []) or [],
                    "waf_suggestions": data.get("waf_suggestions", []) or [],
                    "error": None,
                }
            except json.JSONDecodeError:
                pass
        return {
            "summary": text[:1000] if text else "",
            "sensitive_endpoints": [],
            "waf_suggestions": [],
            "error": "AI không trả về JSON hợp lệ — xem summary thô.",
        }

    async def check_ollama_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                r = await client.get(f"{self.ollama_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def get_available_models(self):
        try:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                r = await client.get(f"{self.ollama_url}/api/tags")
                data = r.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []
