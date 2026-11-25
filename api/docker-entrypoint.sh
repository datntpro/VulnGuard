#!/bin/sh
# N-9: container chạy non-root (uid 10001). Nâng cấp từ image cũ (root) để lại ./storage
# thuộc root → SQLite "readonly database" khó hiểu. Kiểm tra sớm và nói rõ cách sửa.
set -eu
# storage = thư mục cha của thư mục chứa DB (giống api/config.py: …/storage/db/x.db → …/storage)
if [ -z "${VULNGUARD_STORAGE_DIR:-}" ]; then
    case "${DATABASE_URL:-}" in
        sqlite:////*) _p="/${DATABASE_URL#sqlite:////}"; VULNGUARD_STORAGE_DIR="$(dirname "$(dirname "$_p")")" ;;
        *) VULNGUARD_STORAGE_DIR="/app/storage" ;;
    esac
fi
STORAGE="$VULNGUARD_STORAGE_DIR"
fail() {
    echo "❌ $1 không ghi được bởi uid $(id -u) (thường do ./storage có file thuộc root từ phiên bản cũ)." >&2
    echo "   Sửa trên máy host:  sudo chown -R 10001:10001 storage" >&2
    echo "   (không dùng chmod 777). Rồi: docker compose up -d" >&2
    exit 1
}
for d in "$STORAGE" "$STORAGE/db"; do
    mkdir -p "$d" 2>/dev/null || true
    [ -w "$d" ] || fail "$d"
done
# File/thư mục con thuộc root (vd db/vulnguard.db, reports/, .trivy-cache/) cũng làm app lỗi.
_bad=""
for f in $(find "$STORAGE" -maxdepth 3 2>/dev/null | head -n 2000 | tr ' ' '?'); do
    [ -w "$f" ] || { _bad="$f"; break; }
done
[ -z "$_bad" ] || fail "$_bad"
exec "$@"
