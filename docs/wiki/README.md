# Wiki (version-controlled)

Thư mục này là **bản gốc có version control** của GitHub Wiki (`VulnGuard.wiki.git`).
GitHub Wiki là một git repo riêng, **không hỗ trợ Pull Request** và không push được
từ phiên cloud — nên wiki được quản lý ở đây rồi đồng bộ bằng script.

## Quy trình

- Sửa nội dung: chỉnh các file `*.md` trong thư mục này, commit/PR như code bình thường.
- Đẩy lên GitHub Wiki (chạy trên máy đã đăng nhập GitHub có quyền ghi):

  ```bash
  bash docs/wiki/publish-wiki.sh
  ```

- Nếu ai đó lỡ sửa trực tiếp trên web, kéo về để không mất thay đổi:

  ```bash
  bash docs/wiki/publish-wiki.sh pull
  git diff docs/wiki        # xem khác biệt
  git add docs/wiki && git commit -m "docs: sync wiki edits from web"
  ```

> Nguồn chân lý là thư mục này. Hạn chế sửa trực tiếp trên web; nếu có, nhớ `pull` về trước khi `publish`.

## Trang

| File | Trang wiki |
|---|---|
| `Home.md` | Home |
| `_Sidebar.md` / `_Footer.md` | thanh bên / chân trang |
| các `*.md` còn lại | tên trang = tên file (vd `Knowledge-Base.md` → *Knowledge Base*) |

`README.md` và `publish-wiki.sh` **không** được đồng bộ (không phải trang wiki).
