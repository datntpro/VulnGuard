"""BudgetedDriver: bọc LLMDriver thật, cộng dồn token/USD sau mỗi lượt và BUỘC kết thúc khi chạm trần (P1-7, D9).
Giá tính THEO TỪNG LƯỢT (tier theo input_tokens của lượt đó). Model chưa có giá → từ chối ngay (fail closed).
Nguồn sự thật về chi tiêu là llm-relay (đếm mọi lượt gọi); lớp này chỉ là trần mềm theo task để agent kết thúc êm.

P2-15b: `SharedBudget` — MỘT trần USD chung cho mọi driver của một task (planner/executor/summarizer của arch graph, summarizer của
nén context ở legacy): chạm trần ở bất kỳ vai nào thì mọi vai dừng. `local=True` (Ollama): không có bảng giá, USD = 0, vẫn đếm token."""
import threading
from typing import Optional, Union

from eval.harness.prices import MAX_OUTPUT_TOKENS, call_usd, max_call_usd, require_known


class SharedBudget:
    def __init__(self, budget_usd: float):
        self.budget_usd = float(budget_usd)
        self.usd = 0.0
        self.tokens_in = 0
        self.tokens_out = 0
        self.tokens_cache_read = 0
        self.tokens_cache_write = 0
        self.calls = 0
        self._stopped = False
        self.pending = 0.0                       # USD giữ chỗ cho các lượt đang bay (S1)
        self._lock = threading.Lock()

    @property
    def exhausted(self) -> bool:
        return self._stopped or self.usd >= self.budget_usd

    def reserve(self, amount: float) -> bool:
        """Giữ chỗ chi phí xấu nhất của một lượt TRƯỚC khi gửi. False nếu usd + pending + amount sẽ vượt trần (không giữ gì)."""
        with self._lock:
            if self._stopped or self.usd + self.pending + amount > self.budget_usd:
                return False
            self.pending += amount
            return True

    def release(self, amount: float) -> None:
        with self._lock:
            self.pending = max(0.0, self.pending - amount)

    def stop(self) -> None:
        self._stopped = True

    def add(self, usd: float, tin: int, tout: int, cr: int, cw: int) -> None:
        self.usd += usd
        self.tokens_in += tin
        self.tokens_out += tout
        self.tokens_cache_read += cr
        self.tokens_cache_write += cw
        self.calls += 1
        if self.usd >= self.budget_usd:
            self._stopped = True

    def usage(self) -> dict:
        return {"tokens_in": self.tokens_in, "tokens_out": self.tokens_out,
                "tokens_cache_read": self.tokens_cache_read, "tokens_cache_write": self.tokens_cache_write, "usd": round(self.usd, 4),
                "llm_calls": self.calls, "budget_exhausted": self.exhausted}


class BudgetedDriver:
    def __init__(self, inner, budget_usd: Union[float, SharedBudget], local: bool = False):
        model = getattr(inner, "model", None)
        if not isinstance(model, str) or not model:
            raise RuntimeError("BudgetedDriver: driver không có thuộc tính `model` — không thể tính giá")
        if not local:
            require_known(model)                # raise UnknownModel nếu chưa có giá (local/Ollama: miễn phí, không có bảng giá)
        self._inner = inner
        self._model = model
        self._local = local
        self.shared = budget_usd if isinstance(budget_usd, SharedBudget) else SharedBudget(float(budget_usd))
        self.tokens_in = 0                      # thống kê RIÊNG của driver này (shared cộng dồn mọi driver)
        self.tokens_out = 0
        self.tokens_cache_read = 0
        self.tokens_cache_write = 0
        self.calls = 0
        self.usd = 0.0
        self._reserved: dict = {}               # id(raw) → USD giữ chỗ của lượt đó, nhả ở parse (hoặc khi create lỗi)

    @property
    def budget_usd(self) -> float:
        return self.shared.budget_usd

    @property
    def budget_exhausted(self) -> bool:
        return self.shared.exhausted

    def __getattr__(self, name):          # native_tools, create, assistant_entry, tool_result_entries, model, ...
        return getattr(self._inner, name)

    async def create(self, system, messages, native_tools, **kw):
        if self.shared.exhausted:        # không bao giờ gọi thêm sau khi chạm trần (của MỌI vai chung ngân sách)
            self.shared.stop()
            raise RuntimeError(f"budget {self.shared.budget_usd:.2f} USD đã hết")
        reserve = 0.0
        if not self._local:
            # S1: ước lượng xấu nhất = input (byte payload ≥ token, giá cache-write) + max output; các executor song song cùng giữ chỗ
            try:
                est = len(repr(system)) + len(repr(messages)) + len(repr(native_tools))
                reserve = call_usd(self._model, 0, MAX_OUTPUT_TOKENS, 0, est)
            except Exception:
                reserve = max_call_usd(self._model)
            if not self.shared.reserve(reserve):
                if self.shared.pending == 0:          # không còn lượt nào đang bay mà vẫn không vừa ⇒ hết ngân sách thật
                    self.shared.stop()
                raise RuntimeError(f"budget {self.shared.budget_usd:.2f} USD không đủ chỗ cho lượt gọi (đã tính các lượt đang bay)")
        try:
            raw = await self._inner.create(system, messages, native_tools, **kw)
        except BaseException:
            self.shared.release(reserve)
            raise
        self._reserved[id(raw)] = reserve
        return raw

    def parse(self, raw):
        reserve = self._reserved.pop(id(raw), 0.0)
        try:
            res = self._inner.parse(raw)
        except BaseException:
            self.shared.release(reserve)
            raise
        usd = 0.0 if self._local else call_usd(self._model, res.tokens_in, res.tokens_out, res.tokens_cache_read, res.tokens_cache_write)
        self.calls += 1
        self.tokens_in += res.tokens_in
        self.tokens_out += res.tokens_out
        self.tokens_cache_read += res.tokens_cache_read
        self.tokens_cache_write += res.tokens_cache_write
        self.usd += usd
        self.shared.add(usd, res.tokens_in, res.tokens_out, res.tokens_cache_read, res.tokens_cache_write)
        self.shared.release(reserve)             # quyết toán: chi phí thật đã vào usd, nhả phần giữ chỗ
        if self.shared.exhausted:
            res.tool_calls = []          # không chạy thêm tool; agent kết thúc ở lượt này
            res.end = True
        return res

    def usage(self) -> dict:
        """Tổng của CẢ ngân sách chung (mọi vai) — `usd` = chi tiêu của task."""
        return self.shared.usage()
