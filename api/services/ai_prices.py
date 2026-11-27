"""[AI PR-3/PR-6] Bảng giá ước lượng USD / 1M token cho hạn mức org-key (chỉ ƯỚC LƯỢNG, không phải hoá đơn).

Khác eval/harness/prices.py (FAIL CLOSED cho harness): ở đây model lạ KHÔNG được bypass hạn mức. Đơn vị:
(input, output, cache_read) USD / 1M token; cache write = 1.25 × input.

[PR-6 S2] Khớp theo model id CHÍNH XÁC (sau chuẩn hoá tiền tố nhà cung cấp / hậu tố phiên bản-ngày), KHÔNG khớp chuỗi
con/tiền tố: `o3-pro`, `o3-deep-research`, `gpt-4o-mini-xxx` không bao giờ rơi vào giá của `o3`/`gpt-4o`.
Model không có trong bảng → mức ĐẮT NHẤT của họ provider (fail closed): anthropic/bedrock, openai-family, gemini/vertex;
không biết provider → đắt nhất toàn bảng.
"""
import re
from typing import Dict, Optional, Tuple

PRICES: Dict[str, Tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-haiku-5-5": (0.50, 2.50, 0.50),      # tier đắt nhất (prompt > 100K)
    "claude-opus-4-8": (5.00, 25.00, 0.50),
    "gpt-4o-mini": (0.15, 0.60, 0.075),
    "gpt-4o": (2.50, 10.00, 1.25),
    "gpt-4.1-mini": (0.40, 1.60, 0.10),
    "gpt-4.1": (2.00, 8.00, 0.50),
    "o4-mini": (1.10, 4.40, 0.275),
    "o3": (2.00, 8.00, 0.50),
    "o3-pro": (20.00, 80.00, 20.00),
    "o3-deep-research": (10.00, 40.00, 2.50),
    "o1-pro": (150.00, 600.00, 150.00),
    "gemini-2.5-flash-lite": (0.10, 0.40, 0.025),
    "gemini-2.5-flash": (0.30, 2.50, 0.075),
    "gemini-2.5-pro": (2.50, 15.00, 0.625),      # tier prompt > 200K
    "gemini-2.0-flash": (0.10, 0.40, 0.025),
}

# Mức đắt nhất mỗi họ provider (giá cho model KHÔNG có trong bảng). Cố ý ≥ mọi model hiện biết của họ.
_FAMILY_DEFAULT: Dict[str, Tuple[float, float, float]] = {
    "anthropic": (5.00, 25.00, 5.00),
    "openai": (20.00, 80.00, 20.00),             # = o3-pro, mức đắt nhất của dòng phổ thông; o1-pro khai báo riêng
    "google": (5.00, 30.00, 1.25),
}
_PROVIDER_FAMILY = {"anthropic": "anthropic", "bedrock": "anthropic", "openai": "openai", "openrouter": "openai",
                    "azure_openai": "openai", "openai_compatible": "openai", "gemini": "google", "vertex": "google"}
DEFAULT = tuple(max(v[i] for v in _FAMILY_DEFAULT.values()) for i in range(3))   # không rõ provider → đắt nhất toàn bảng

UNMAPPED = "unmapped/"
_PREFIX = re.compile(r"^(?:(?:us|eu|apac|global|au|jp)\.)?(?:anthropic|openai|google|azure|models)[./:]", re.I)
_SUFFIXES = (re.compile(r"-v\d+(?::\d+)?$"), re.compile(r"@\d{8}$"), re.compile(r"-\d{8}$"),
             re.compile(r"-\d{4}-\d{2}-\d{2}$"), re.compile(r"-latest$"))


def normalize_model(model: str) -> str:
    """'anthropic.claude-opus-5-5-v1:0' → 'claude-opus-5-5'; 'openai/gpt-4o-2024-08-06' → 'gpt-4o'. Không đoán thêm."""
    m = (model or "").strip().lower()
    if m.startswith(UNMAPPED):      # [re-verify L3] marker "deployment chưa ánh xạ" được GIỮ nguyên → không bao giờ trông như model rẻ
        return m
    for _ in range(3):
        n = _PREFIX.sub("", m)
        if n == m:
            break
        m = n
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            n = suf.sub("", m)
            if n != m:
                m, changed = n, True
    return m


def is_known(model: str) -> bool:
    return normalize_model(model) in PRICES


def default_for(provider: Optional[str]) -> Tuple[float, float, float]:
    fam = _PROVIDER_FAMILY.get((provider or "").lower())
    return _FAMILY_DEFAULT[fam] if fam else DEFAULT


def _lookup(model: str, provider: Optional[str] = None) -> Tuple[float, float, float]:
    return PRICES.get(normalize_model(model)) or default_for(provider)


def est_cost_usd(model: str, tokens_in: int = 0, tokens_out: int = 0, cache_read: int = 0, cache_write: int = 0,
                 provider: Optional[str] = None) -> float:
    pin, pout, pread = _lookup(model, provider)
    return (int(tokens_in) * pin + int(cache_write) * pin * 1.25 + int(cache_read) * pread
            + int(tokens_out) * pout) / 1_000_000
