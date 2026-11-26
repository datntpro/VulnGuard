#!/usr/bin/env bash
# P2-15b: bench với LLM LOCAL (Ollama, OpenAI-compatible) trên máy này, trong lab Docker cô lập hiện có. 0 USD; vẫn đếm token.
# KHÔNG dùng ở CI (runner không với tới Ollama). Mặc định chạy CẢ HAI arch (legacy rồi graph) với MỘT model cho mọi vai.
#
#   make bench-local                                              # suite stub,injection + 3 XBOW (core)
#   make bench-local BENCH_SUITE=stub,injection BENCH_TASKS=      # chỉ 2 suite nhanh
#   make bench-local BENCH_MODEL=qwen2.5:7b BENCH_ARCH=legacy
#
# Yêu cầu: Docker, `ollama serve` đã chạy và đã `ollama pull $BENCH_MODEL` (model phải hỗ trợ tool calling).
# Relay (container duy nhất có egress) nói chuyện với Ollama qua host.docker.internal:11434 (Docker Desktop). Ollama mặc định chỉ nghe
# 127.0.0.1 — Docker Desktop vẫn tới được; nếu relay báo lỗi upstream trên Linux, đặt OLLAMA_HOST=0.0.0.0 (cẩn thận mạng).
# Ngữ cảnh: Ollama mặc định num_ctx nhỏ → prompt của agent bị cắt IM LẶNG. Chạy `ollama serve` với OLLAMA_CONTEXT_LENGTH=16384 (hoặc lớn hơn).
set -euo pipefail
cd "$(dirname "$0")/../.."
PY="${PY:-python3}"
SUITE="${BENCH_SUITE:-stub,injection,xbow}"
TASKS="${BENCH_TASKS-XBEN-004-24,XBEN-005-24,XBEN-007-24}"
ARCH="${BENCH_ARCH:-both}"
MODEL="${BENCH_MODEL:-qwen2.5:7b}"
OUT="${BENCH_OUT:-eval/out}"
LAB="-f eval/lab/docker-compose.lab.yml -f eval/lab/docker-compose.capability.yml"
export COMPOSE_PROFILES=capability VG_LAB=1
unset ANTHROPIC_API_KEY            # chế độ local KHÔNG bao giờ dùng/forward khoá thật

curl -fsS http://localhost:11434/api/tags | grep -q "\"$MODEL\"" || { echo "Ollama không chạy hoặc chưa pull $MODEL (ollama pull $MODEL)"; exit 1; }
TASK_ARGS=(); [ -n "$TASKS" ] && TASK_ARGS=(--tasks "$TASKS")
docker image inspect vulnguard-lab:latest >/dev/null 2>&1 || docker build -q -t vulnguard-lab:latest -f api/Dockerfile .
case ",$SUITE," in *,xbow,*|*,core,*|*,full,*|*,autopenbench,*) "$PY" -m eval.harness.bench --prepare --suite "$SUITE" "${TASK_ARGS[@]}" ;; esac
trap 'docker compose $LAB down -v >/dev/null 2>&1 || true' EXIT
docker compose $LAB up -d --no-build vg-under-test capture
for _ in $(seq 1 30); do docker exec vg-under-test getent hosts inscope.lab stub-flag.lab >/dev/null 2>&1 && break; sleep 2; done
"$PY" -m eval.harness.bench --suite "$SUITE" --arch "$ARCH" --driver real --provider ollama --model "$MODEL" "${TASK_ARGS[@]}" --out "$OUT"
"$PY" -m eval.harness.bench --check-safety "$OUT"
