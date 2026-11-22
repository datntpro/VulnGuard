#!/usr/bin/env bash
# VulnGuard — cài đặt (macOS/Linux). Windows: dùng setup.ps1 hoặc Docker.
# Logic chung ở scripts/setup.py (đa nền tảng). Dùng: bash setup.sh [--check|--docker|--tools ... --no-run]
cd "$(dirname "$0")" || exit 1
PY="$(command -v python3 || command -v python)"
[ -z "$PY" ] && { echo "❌ Cần Python 3.11+ (python.org)"; exit 1; }
exec "$PY" scripts/setup.py "$@"
