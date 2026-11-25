"""Bảng giá USD / 1M token (CHỈNH TAY khi giá đổi). Dùng để ước lượng chi phí của run capability (P1-7, D9).
Ước lượng bảo thủ: không trừ giá cache-read (agent legacy không bật prompt caching)."""
from typing import Dict, Tuple

PRICES: Dict[str, Tuple[float, float]] = {       # model → (input $/MTok, output $/MTok)
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}
# Model chưa có trong bảng → giá đắt nhất (fail closed về phía chi nhiều hơn ước lượng, không bao giờ ít hơn).
_FALLBACK = max(PRICES.values())

MODEL_PROFILES: Dict[str, str] = {                # D1: legacy single-agent dùng 1 model cho mọi vai
    "opus": "claude-opus-5-5",
    "sonnet": "claude-sonnet-5-5",
    "haiku": "claude-haiku-5-5",
}


def estimate_usd(model: str, tokens_in: int, tokens_out: int) -> float:
    pin, pout = PRICES.get(model, _FALLBACK)
    return (tokens_in * pin + tokens_out * pout) / 1_000_000


def max_tokens_for_budget(model: str, budget_usd: float) -> int:
    """Số token tổng tối đa nếu TOÀN BỘ là token output (đắt nhất) — dùng làm `Engagement.max_tokens` (lưới an toàn thứ hai).
    Agent cộng in+out vào cùng một bộ đếm nên giá trị này luôn ≥ chi phí thật chia cho giá rẻ nhất → tối thiểu hoá rủi ro vượt."""
    _, pout = PRICES.get(model, _FALLBACK)
    return max(1000, int(budget_usd / pout * 1_000_000))
