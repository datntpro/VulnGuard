"""BudgetedDriver: bọc LLMDriver thật, cộng dồn token/USD sau mỗi lượt và BUỘC kết thúc khi chạm trần (P1-7, D9)."""
from eval.harness.prices import estimate_usd


class BudgetedDriver:
    def __init__(self, inner, budget_usd: float):
        self._inner = inner
        self.budget_usd = float(budget_usd)
        self.tokens_in = 0
        self.tokens_out = 0
        self.calls = 0
        self.budget_exhausted = False

    def __getattr__(self, name):          # native_tools, create, assistant_entry, tool_result_entries, model, ...
        return getattr(self._inner, name)

    @property
    def usd(self) -> float:
        return estimate_usd(getattr(self._inner, "model", ""), self.tokens_in, self.tokens_out)

    async def create(self, system, messages, native_tools):
        if self.budget_exhausted or self.usd >= self.budget_usd:   # không bao giờ gọi thêm sau khi chạm trần
            self.budget_exhausted = True
            raise RuntimeError(f"budget {self.budget_usd:.2f} USD đã hết")
        return await self._inner.create(system, messages, native_tools)

    def parse(self, raw):
        res = self._inner.parse(raw)
        self.calls += 1
        self.tokens_in += res.tokens_in
        self.tokens_out += res.tokens_out
        if self.usd >= self.budget_usd:
            self.budget_exhausted = True
            res.tool_calls = []          # không chạy thêm tool; agent kết thúc ở lượt này
            res.end = True
        return res

    def usage(self) -> dict:
        return {"tokens_in": self.tokens_in, "tokens_out": self.tokens_out, "usd": round(self.usd, 4),
                "llm_calls": self.calls, "budget_exhausted": self.budget_exhausted}
