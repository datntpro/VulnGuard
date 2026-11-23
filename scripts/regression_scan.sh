#!/usr/bin/env bash
# 1.8: Chạy bộ test hồi quy phát hiện lỗ hổng tại LOCAL (GitHub Actions có thể bị chặn billing).
# Yêu cầu: đã cài scanner trong .venv (bash setup.sh). Fail nếu số lỗi tìm được tụt về 0.
set -euo pipefail
cd "$(dirname "$0")/.."
VENV="${VULNGUARD_VENV:-.venv}"
# Đưa scanner trong venv lên PATH để test tìm thấy (semgrep/bandit…)
export PATH="$PWD/$VENV/bin:$HOME/.local/bin:$PATH"
echo "▶ Chạy test hồi quy phát hiện (repo mẫu có lỗi đã biết)…"
"$VENV/bin/python" -m pytest tests/test_regression_detection.py tests/test_p0_safety.py -v
echo "✅ Hồi quy OK — scanner vẫn phát hiện lỗ hổng trên fixture."
