#!/usr/bin/env bash
# Publish các trang trong docs/wiki/ lên GitHub Wiki của repo.
# Yêu cầu: đã BẬT Wiki (Settings → Features → Wikis) và bạn có quyền push.
# Chạy TỪ MÁY BẠN (nơi có credential GitHub), tại gốc repo:  bash docs/wiki/publish-wiki.sh
set -euo pipefail
REPO_URL="${WIKI_REPO:-https://github.com/datntpro/VulnGuard.wiki.git}"
SRC="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
echo "▶ Clone wiki: $REPO_URL"
git clone "$REPO_URL" "$TMP" || {
  echo "⚠ Wiki chưa khởi tạo. Vào tab Wiki trên GitHub, bấm 'Create the first page' (lưu 1 trang bất kỳ), rồi chạy lại script."
  exit 1; }
cp "$SRC"/*.md "$TMP"/
cd "$TMP"
git add -A
git -c user.name="VulnGuard" -c user.email="wiki@vulnguard.local" commit -m "docs(wiki): cập nhật nội dung từ docs/wiki" || { echo "Không có thay đổi."; exit 0; }
git push
echo "✅ Đã đẩy $(ls "$SRC"/*.md | wc -l) trang lên Wiki."
