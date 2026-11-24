#!/usr/bin/env bash
# Đồng bộ các trang wiki trong docs/wiki/ lên GitHub Wiki của repo.
#
# Wiki là một git repo RIÊNG (<repo>.wiki.git) — không thể push từ phiên cloud
# (GitHub API không expose wiki như repo). Chạy script này TRÊN MÁY BẠN, nơi đã
# đăng nhập GitHub có quyền ghi.
#
# Dùng:  bash docs/wiki/publish-wiki.sh [owner/repo]
#   mặc định owner/repo = datntpro/VulnGuard
set -euo pipefail

REPO="${1:-datntpro/VulnGuard}"
SRC="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "→ Clone wiki: https://github.com/${REPO}.wiki.git"
git clone "https://github.com/${REPO}.wiki.git" "$TMP/wiki"

echo "→ Copy các trang từ ${SRC}"
for f in "$SRC"/*.md; do
  cp "$f" "$TMP/wiki/$(basename "$f")"
done

cd "$TMP/wiki"
if git diff --quiet && git diff --cached --quiet; then
  echo "✓ Không có thay đổi — wiki đã mới nhất."
  exit 0
fi
git add -A
git commit -m "docs: cập nhật trang Knowledge Base (OSV+EPSS+KEV)"
git push origin HEAD
echo "✓ Đã publish wiki."
