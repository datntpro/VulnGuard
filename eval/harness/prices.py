"""Bảng giá USD / 1M token (CHỈNH TAY khi giá đổi). Dùng để ước lượng chi phí của run capability (P1-7, D9).
File này là NGUỒN DUY NHẤT: harness import trực tiếp, llm-relay mount read-only (stdlib thuần — không import gì từ repo).
Cache-aware (P2-9b) nhưng KHÔNG BAO GIỜ tính thấp hơn giá niêm yết: cache write = 1.25× giá input (TTL 5 phút);
cache read = giá read niêm yết trong CACHE_READ, model không có trong đó → tính bằng giá input đầy đủ (bảo thủ).
FAIL CLOSED: model không có trong bảng → UnknownModel (không bao giờ đoán giá)."""
from typing import Dict, List, Tuple

# model → [(trần input_tokens của MỘT lượt gọi, input $/MTok, output $/MTok), ...] theo tier tăng dần; tier cuối = vô hạn.
PRICES: Dict[str, List[Tuple[float, float, float]]] = {
    "claude-opus-5-5": [(float("inf"), 4.00, 20.00)],
    "claude-sonnet-5-5": [(float("inf"), 2.00, 10.00)],
    # Haiku 5.5: prompt > 100K token tính giá gấp 5 (0.50 / 2.50)
    "claude-haiku-5-5": [(100_000, 0.10, 0.50), (float("inf"), 0.50, 2.50)],
}

MODEL_PROFILES: Dict[str, str] = {                # D1: legacy single-agent dùng 1 model cho mọi vai
    "opus": "claude-opus-5-5",
    "sonnet": "claude-sonnet-5-5",
    "haiku": "claude-haiku-5-5",
}

# model → giá cache-read $/MTok (theo bảng giá công bố). Model không có ở đây → read tính bằng giá input (bảo thủ).
CACHE_READ: Dict[str, float] = {"claude-opus-5-5": 0.20, "claude-sonnet-5-5": 0.10}
CACHE_WRITE_MULT = 1.25          # TTL 5 phút (không dùng TTL 1 giờ)

MAX_OUTPUT_TOKENS = 8000          # LLMDriver.create luôn dùng 8000
MAX_CONTEXT_TOKENS = 200_000      # trần input giả định cho MỘT lượt (ước lượng lượt gọi đắt nhất)


class UnknownModel(RuntimeError):
    pass


def _tier(model: str, tokens_in: int) -> Tuple[float, float]:
    tiers = PRICES.get(model)
    if not tiers:
        raise UnknownModel(f"model {model!r} chưa có trong bảng giá (eval/harness/prices.py) — từ chối chạy")
    for cap, pin, pout in tiers:
        if tokens_in <= cap:
            return pin, pout
    return tiers[-1][1], tiers[-1][2]


def call_usd(model: str, tokens_in: int, tokens_out: int, cache_read: int = 0, cache_write: int = 0) -> float:
    """Giá của MỘT lượt gọi. `tokens_in` = phần input KHÔNG cache (usage.input_tokens). Tier theo kích thước prompt THẬT."""
    total_prompt = int(tokens_in) + int(cache_read) + int(cache_write)
    pin, pout = _tier(model, total_prompt)
    pread = CACHE_READ.get(model, pin)
    return (tokens_in * pin + cache_write * pin * CACHE_WRITE_MULT + cache_read * pread + tokens_out * pout) / 1_000_000


def estimate_usd(model: str, tokens_in: int, tokens_out: int) -> float:
    """Ước lượng từ tổng cộng dồn: bảo thủ — dùng tier ĐẮT NHẤT nếu model có tier."""
    tiers = PRICES.get(model)
    if not tiers:
        raise UnknownModel(f"model {model!r} chưa có trong bảng giá")
    _, pin, pout = tiers[-1]
    return (tokens_in * pin + tokens_out * pout) / 1_000_000


def max_call_usd(model: str) -> float:
    """Chi phí tối đa có thể của MỘT lượt gọi (context trần + output tối đa) — phần vượt trần tối đa của mỗi task."""
    return call_usd(model, MAX_CONTEXT_TOKENS, MAX_OUTPUT_TOKENS)


def require_known(model: str) -> None:
    _tier(model, 0)


def max_tokens_for_budget(model: str, budget_usd: float) -> int:
    """`Engagement.max_tokens` (lưới thứ hai, in+out gộp): tính theo giá INPUT rẻ nhất — token chủ yếu là input nên giá trị này
    đủ rộng để TRẦN USD (BudgetedDriver + relay) là giới hạn thực sự, không phải số token."""
    pin = min(t[1] for t in PRICES[model]) if model in PRICES else None
    if pin is None:
        raise UnknownModel(f"model {model!r} chưa có trong bảng giá")
    return max(1000, int(budget_usd / pin * 1_000_000))
