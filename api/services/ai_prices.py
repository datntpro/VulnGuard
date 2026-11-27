"""[AI PR-3] Bảng giá ước lượng USD / 1M token cho hạn mức org-key (chỉ ƯỚC LƯỢNG, không phải hoá đơn).

Khác eval/harness/prices.py (FAIL CLOSED cho harness): ở đây model lạ KHÔNG được bypass hạn mức → dùng giá bảo thủ
(đắt) `DEFAULT`. Đơn vị: (input, output, cache_read) USD / 1M token; cache write = 1.25 × input.
"""
from typing import Dict, Tuple

PRICES: Dict[str, Tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-haiku-5-5": (0.50, 2.50, 0.50),      # tier đắt nhất (prompt > 100K)
    "claude-opus-4-8": (5.00, 25.00, 0.50),
    "gpt-4o": (2.50, 10.00, 1.25),
}
DEFAULT = (5.00, 25.00, 5.00)


def _lookup(model: str) -> Tuple[float, float, float]:
    m = (model or "").lower()
    # Bedrock/OpenRouter thêm tiền tố ("anthropic.claude-…", "anthropic/claude-…", hậu tố phiên bản)
    for name, price in PRICES.items():
        if name in m:
            return price
    return DEFAULT


def est_cost_usd(model: str, tokens_in: int = 0, tokens_out: int = 0, cache_read: int = 0, cache_write: int = 0) -> float:
    pin, pout, pread = _lookup(model)
    return (int(tokens_in) * pin + int(cache_write) * pin * 1.25 + int(cache_read) * pread
            + int(tokens_out) * pout) / 1_000_000
