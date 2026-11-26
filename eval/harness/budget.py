"""BudgetedDriver: bọc LLMDriver thật, cộng dồn token/USD sau mỗi lượt và BUỘC kết thúc khi chạm trần (P1-7, D9).
Giá tính THEO TỪNG LƯỢT (tier theo input_tokens của lượt đó). Model chưa có giá → từ chối ngay (fail closed).
Nguồn sự thật về chi tiêu là llm-relay (đếm mọi lượt gọi); lớp này chỉ là trần mềm theo task để agent kết thúc êm."""
from eval.harness.prices import call_usd, require_known


class BudgetedDriver:
    def __init__(self, inner, budget_usd: float):
        model = getattr(inner, "model", None)
        if not isinstance(model, str) or not model:
            raise RuntimeError("BudgetedDriver: driver không có thuộc tính `model` — không thể tính giá")
        require_known(model)                    # raise UnknownModel nếu chưa có giá
        self._inner = inner
        self._model = model
        self.budget_usd = float(budget_usd)
        self.tokens_in = 0
        self.tokens_out = 0
        self.tokens_cache_read = 0
        self.tokens_cache_write = 0
        self.calls = 0
        self.usd = 0.0
        self.budget_exhausted = False

    def __getattr__(self, name):          # native_tools, create, assistant_entry, tool_result_entries, model, ...
        return getattr(self._inner, name)

    async def create(self, system, messages, native_tools, **kw):
        if self.budget_exhausted or self.usd >= self.budget_usd:   # không bao giờ gọi thêm sau khi chạm trần
            self.budget_exhausted = True
            raise RuntimeError(f"budget {self.budget_usd:.2f} USD đã hết")
        return await self._inner.create(system, messages, native_tools, **kw)

    def parse(self, raw):
        res = self._inner.parse(raw)
        self.calls += 1
        self.tokens_in += res.tokens_in
        self.tokens_out += res.tokens_out
        self.tokens_cache_read += res.tokens_cache_read
        self.tokens_cache_write += res.tokens_cache_write
        self.usd += call_usd(self._model, res.tokens_in, res.tokens_out, res.tokens_cache_read, res.tokens_cache_write)
        if self.usd >= self.budget_usd:
            self.budget_exhausted = True
            res.tool_calls = []          # không chạy thêm tool; agent kết thúc ở lượt này
            res.end = True
        return res

    def usage(self) -> dict:
        return {"tokens_in": self.tokens_in, "tokens_out": self.tokens_out,
                "tokens_cache_read": self.tokens_cache_read, "tokens_cache_write": self.tokens_cache_write, "usd": round(self.usd, 4),
                "llm_calls": self.calls, "budget_exhausted": self.budget_exhausted}
