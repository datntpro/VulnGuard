#!/usr/bin/env bash
# Version-control cho GitHub Wiki: đồng bộ 2 chiều giữa docs/wiki/ và wiki repo.
#
# Wiki là một git repo RIÊNG (<repo>.wiki.git) — không có cơ chế Pull Request và
# KHÔNG push được từ phiên cloud (proxy không cấp credential cho .wiki). Chạy
# script này TRÊN MÁY BẠN, nơi đã đăng nhập GitHub có quyền ghi.
#
# Dùng:
#   bash docs/wiki/publish-wiki.sh [publish|pull] [owner/repo]
#
#   publish  (mặc định) : docs/wiki/*.md  →  wiki   (repo là nguồn chân lý)
#   pull                : wiki  →  docs/wiki/*.md    (kéo bản sửa trên web về repo
#                                                     để commit vào version control)
#   owner/repo mặc định = datntpro/VulnGuard
#
# File KHÔNG phải trang wiki (README.md, publish-wiki.sh) được loại khỏi đồng bộ.
set -euo pipefail

MODE="${1:-publish}"
REPO="${2:-datntpro/VulnGuard}"
SRC="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Trang wiki = *.md trừ README.md
_is_page() { [ "$(basename "$1")" != "README.md" ]; }

echo "→ Clone wiki: https://github.com/${REPO}.wiki.git"
git clone "https://github.com/${REPO}.wiki.git" "$TMP/wiki"

case "$MODE" in
  publish)
    echo "→ publish: docs/wiki/ → wiki"
    for f in "$SRC"/*.md; do
      _is_page "$f" && cp "$f" "$TMP/wiki/$(basename "$f")"
    done
    cd "$TMP/wiki"
    if git diff --quiet && git diff --cached --quiet; then
      echo "✓ Không có thay đổi — wiki đã mới nhất."; exit 0
    fi
    git add -A
    git commit -m "docs: đồng bộ wiki từ docs/wiki/ (version control)"
    git push origin HEAD
    echo "✓ Đã publish wiki."
    ;;
  pull)
    echo "→ pull: wiki → docs/wiki/"
    for f in "$TMP/wiki"/*.md; do
      _is_page "$f" && cp "$f" "$SRC/$(basename "$f")"
    done
    echo "✓ Đã kéo wiki về docs/wiki/. Kiểm tra 'git diff' rồi commit vào repo."
    ;;
  *)
    echo "Sai tham số. Dùng: publish | pull" >&2; exit 2
    ;;
esac
