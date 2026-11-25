#!/bin/sh
# N-9: container chạy non-root (uid 10001). Nâng cấp từ image cũ (root) để lại ./storage
# thuộc root → SQLite "readonly database" khó hiểu. Kiểm tra sớm và nói rõ cách sửa.
set -eu
STORAGE="${VULNGUARD_STORAGE_DIR:-/app/storage}"
for d in "$STORAGE" "$STORAGE/db"; do
    mkdir -p "$d" 2>/dev/null || true
    if [ ! -w "$d" ]; then
        echo "❌ $d không ghi được bởi uid $(id -u) (thường do ./storage thuộc root từ phiên bản cũ)." >&2
        echo "   Sửa trên máy host:  sudo chown -R 10001:10001 storage" >&2
        echo "   (không dùng chmod 777). Rồi: docker compose up -d" >&2
        exit 1
    fi
done
exec "$@"
