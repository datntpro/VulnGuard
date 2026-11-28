# Runbook xoay khoá AI / AI key & secret-key rotation runbook

> Khớp mã nguồn `main` (`api/services/ai_credentials.py`, `api/security.py`). Tiếng Anh ở cuối ([jump](#english)). Liên quan: [[Per-user AI keys|AI-Per-User-Keys]].

---

## Tiếng Việt

### 0. Nguyên tắc: bản sao lưu và secret key phải cất RIÊNG

Khoá AI trong DB (`ai_credentials.secret_enc`) là Fernet được dẫn xuất từ **secret key của ứng dụng** (`VULNGUARD_SECRET_KEY` hoặc `storage/secret.key`). Ai có **cả** bản sao lưu DB **và** secret key thì giải mã được mọi khoá.

- Lưu **bản sao lưu DB/`storage/`** và **secret key** ở hai nơi, hai quyền truy cập khác nhau (ví dụ secret key trong secret manager / `.env` của vận hành; backup ở kho lưu trữ khác). Đừng chép `storage/secret.key` vào cùng gói backup với `storage/db/`.
- Nhưng **mất secret key = mất mọi secret đã mã hoá** (AI, SCM, SMTP…). Hãy có bản sao secret key có kiểm soát (két/secret manager), kiểm thử khôi phục định kỳ: khôi phục DB + secret key trên máy thử, bấm **Test** một khoá.
- Đặt `VULNGUARD_SECRET_KEY` cố định bằng biến môi trường khi chạy nhiều instance hoặc cần xoay có kiểm soát. Không commit `storage/` (`secret.key`, `ai_config.json` không nằm trong `.gitignore`).

### 1. Xoay MỘT khoá AI (hằng ngày, không gián đoạn)

**Khoá cá nhân** (chủ khoá tự làm): Settings › AI › Khoá AI của tôi › **Thay khoá** (`PUT /api/me/ai-credentials/{id}/secret`). Khoá mới được kiểm tra trước, rồi thay nguyên tử; job ghim vào khoá đó dùng secret mới ở lần gọi kế tiếp. Sau đó **vô hiệu khoá cũ ở provider** (Anthropic Console / AWS IAM `update-service-specific-credential --status Inactive`).

**Khoá tổ chức** (ADMIN): Settings › AI › Cloud AI của tổ chức › nhập key mới › Test (dùng giá trị chưa lưu) › Lưu. Rồi vô hiệu key cũ ở provider.

**Khoá bị lộ / nhân sự nghỉ**: ADMIN thu hồi (`POST /api/ai/credentials/{id}/revoke`), job ghim → `AI_CRED_REVOKED` (Pentest `PAUSED`); **phải** vô hiệu khoá ở provider; yêu cầu chủ thêm khoá mới; resume run bị `PAUSED`. Rà `GET /api/ai/usage?scope=all` và nhật ký `vulnguard.audit.ai` quanh thời điểm nghi lộ.

Tombstone: khoá bị xoá/thu hồi giữ 30 ngày chỉ để tra id (secret đã xoá); usage 180 ngày.

### 2. Xoay SECRET KEY của ứng dụng

> **Cảnh báo phạm vi.** Đổi secret key có tác động rộng hơn khoá AI:
> - **Mọi phiên đăng nhập** (JWT ký bằng cùng khoá) hết hiệu lực: người dùng đăng nhập lại.
> - **Khoá AI trong `ai_credentials`** hỗ trợ xoay có kiểm soát (dưới đây).
> - **Các secret dùng hộp secret chung** (`api.security.encrypt_secret`): token SCM, thông tin connector, SMTP/Sonar trong `runtime_settings.json`, tài khoản test của Pentest, store đồ thị Pentest, và các trường `api_key_enc` cũ trong `ai_config.json` (giữ để rollback) — **chưa có công cụ xoay**. `VULNGUARD_SECRET_KEY_PREVIOUS` chỉ áp cho khoá AI. Sau khi đổi key, những secret này **không giải mã được** (log `Không giải mã được secret — secret key đã đổi?`) và phải **nhập lại**.
> Vì vậy chỉ xoay secret key khi nghi ngờ lộ secret key, hoặc đã sẵn sàng nhập lại các secret trên.

Quy trình (bảo trì có hẹn giờ):

1. **Sao lưu** `storage/` (DB + file cấu hình) **và** secret key cũ, mỗi thứ nơi riêng (mục 0). Ghi lại secret key cũ an toàn.
2. Kiểm kê secret dùng hộp chung cần nhập lại (SCM, connector, SMTP, Sonar, tài khoản test Pentest).
3. Sinh khoá mới: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
4. Dừng ứng dụng (và `pentest-worker` nếu chạy). Không để job chạy trong lúc xoay.
5. Đặt biến môi trường cho **một lần chạy** re-encrypt (trong container `vulnguard` của `docker-compose.yml`, hoặc môi trường native):

```sh
VULNGUARD_SECRET_KEY='<khoá mới>' \
VULNGUARD_SECRET_KEY_PREVIOUS='<khoá cũ>' \
python -c "from api.database import SessionLocal; from api.services import ai_credentials as c; db=SessionLocal(); print('re-encrypted rows:', c.reencrypt_all(db)); db.close()"
```

   Nếu chạy bằng Docker Compose, dùng container một lần (ứng dụng đã dừng):

```sh
docker compose run --rm \
  -e VULNGUARD_SECRET_KEY='<khoá mới>' -e VULNGUARD_SECRET_KEY_PREVIOUS='<khoá cũ>' \
  vulnguard python -c "from api.database import SessionLocal; from api.services import ai_credentials as c; db=SessionLocal(); print('re-encrypted rows:', c.reencrypt_all(db)); db.close()"
```

   Hoặc `docker run --rm` với cùng hai biến `-e`, cùng image và cùng volume `storage/` như dịch vụ `vulnguard`. Lưu ý: đổi `VULNGUARD_SECRET_KEY` làm **mọi phiên đăng nhập (JWT) hết hiệu lực**.
   Số hàng in ra phải bằng số credential có secret. `MultiFernet` giải mã bằng cả hai khoá và mã lại bằng khoá mới. Lưu ý: `reencrypt_all` chạy một transaction rồi commit; nếu bị ngắt giữa chừng, khôi phục từ bản sao lưu bước 1.
6. Đặt `VULNGUARD_SECRET_KEY=<khoá mới>` vĩnh viễn (và bỏ `storage/secret.key` cũ chỉ khi chắc chắn không còn dùng; nếu dùng file thì ghi khoá mới vào đó, quyền `0600`). **Giữ** `VULNGUARD_SECRET_KEY_PREVIOUS` tới khi xác nhận xong.
7. Khởi động lại. Kiểm tra: đăng nhập, **Test** vài khoá cá nhân và khoá tổ chức, chạy một scan nhỏ có AI. Log không được có `không giải mã được credential`.
8. Nhập lại các secret hộp chung (mục kiểm kê). Xoá `VULNGUARD_SECRET_KEY_PREVIOUS`, huỷ bản lưu khoá cũ theo chính sách sau khoảng quan sát (ví dụ 7 ngày) — **giữ bản sao lưu DB cũ đi kèm khoá cũ** nếu cần khôi phục; hai thứ này phải cất riêng (mục 0).

Rollback: dừng app, khôi phục `storage/` từ bước 1, đặt lại `VULNGUARD_SECRET_KEY` cũ, bỏ biến `…_PREVIOUS`.

### 3. Rủi ro còn lại cần biết (LOW, #109)

- **Khôi phục hàng cũ nguyên khối**: người/ tiến trình có quyền ghi DB có thể ghi lại cả hàng `ai_credentials` cũ (kèm `secret_enc` cũ). Envelope ràng buộc id/chủ/provider/`secret_gen`/tham số, nhưng không ngăn "quay về đúng bản cũ" nếu khoá cũ còn hợp lệ ở provider. Giảm thiểu: vô hiệu khoá cũ ở provider ngay khi xoay; quyền ghi DB chỉ cho tiến trình ứng dụng; backup cất riêng.
- **Che khoá trong log**: bộ lọc log quét theo khối 32 KB; một khoá nằm vắt qua ranh giới khối có thể để lộ một tiền tố (~22 ký tự của khoá `sk-proj-…`). Đừng bật log DEBUG của SDK ở production (ứng dụng từ chối khởi động nếu `ANTHROPIC_LOG`/`OPENAI_LOG` = debug). Coi nhật ký là dữ liệu nhạy cảm; hạn chế quyền đọc.
- Bộ lọc log có thể che **quá tay** vài định danh dài chữ hoa/thường lẫn lộn (chỉ ảnh hưởng log, không ảnh hưởng dữ liệu).
- Co-work: redact egress còn các biến thể lạ (`docker -p'X'`, `npm config set _password X`) chưa bắt; mọi lệnh `exec` vẫn cần duyệt của người dùng.

---

## English

### 0. Principle: keep backups and the secret key APART

AI keys in the DB (`ai_credentials.secret_enc`) are Fernet-encrypted with a sub-key derived from the **application secret key** (`VULNGUARD_SECRET_KEY` or `storage/secret.key`). Anyone holding **both** a DB backup and the secret key can decrypt every key.

- Store the **DB / `storage/` backups** and the **secret key** in different places with different access (e.g. the key in a secret manager / ops-owned `.env`, backups in another store). Do not put `storage/secret.key` in the same archive as `storage/db/`.
- But **losing the secret key means losing every encrypted secret** (AI, SCM, SMTP…). Keep a controlled copy of the key (vault/secret manager) and test restores: restore DB + key on a scratch host and press **Test** on one key.
- Pin `VULNGUARD_SECRET_KEY` in the environment for multi-instance or controlled rotation. Never commit `storage/`.

### 1. Rotating ONE AI key (routine, no downtime)

- **Personal key** (the owner): Settings › AI › My AI keys › **Replace** (`PUT /api/me/ai-credentials/{id}/secret`). The new key is validated first, then swapped atomically; jobs pinned to it use the new secret on their next call. Then **disable the old key at the provider**.
- **Org key** (ADMIN): Settings › AI › Organisation cloud AI › enter new key › Test (uses unsaved values) › Save. Then disable the old key at the provider.
- **Leaked key / offboarding**: ADMIN revokes (`POST /api/ai/credentials/{id}/revoke`); pinned jobs → `AI_CRED_REVOKED` (Pentest `PAUSED`); you **must** disable it at the provider; the owner adds a new key; resume paused runs. Review `GET /api/ai/usage?scope=all` and the `vulnguard.audit.ai` log around the suspected time.

Tombstones keep a deleted/revoked row for 30 days (id lookup only; the secret is already wiped); usage events 180 days.

### 2. Rotating the application SECRET KEY

> **Scope warning.** Changing the secret key is broader than AI keys:
> - **All login sessions** (JWT signed with the same key) become invalid.
> - **AI keys in `ai_credentials`** support controlled rotation (below).
> - **Secrets using the shared box** (`api.security.encrypt_secret`): SCM tokens, connector credentials, SMTP/Sonar in `runtime_settings.json`, Pentest test accounts and graph store, and the legacy `api_key_enc` fields in `ai_config.json` (kept for rollback) have **no rotation tool**. `VULNGUARD_SECRET_KEY_PREVIOUS` only applies to AI keys. After the change these fail to decrypt (`Không giải mã được secret — secret key đã đổi?`) and must be **re-entered**.
> Rotate the secret key only if you suspect the key itself leaked, or you are ready to re-enter those secrets.

Procedure (planned maintenance window):

1. **Back up** `storage/` (DB + config files) **and** the old secret key, each in a separate place (section 0).
2. Inventory the shared-box secrets you will re-enter.
3. Generate a key: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
4. Stop the app (and `pentest-worker` if used). No jobs may run during rotation.
5. Run the one-off re-encrypt with the Vietnamese command above (new key as `VULNGUARD_SECRET_KEY`, old key as `VULNGUARD_SECRET_KEY_PREVIOUS`) inside the `vulnguard` container or native environment. With Docker Compose use a one-off container (app stopped):

```sh
docker compose run --rm \
  -e VULNGUARD_SECRET_KEY='<new key>' -e VULNGUARD_SECRET_KEY_PREVIOUS='<old key>' \
  vulnguard python -c "from api.database import SessionLocal; from api.services import ai_credentials as c; db=SessionLocal(); print('re-encrypted rows:', c.reencrypt_all(db)); db.close()"
```

   The plain `docker run --rm` equivalent takes the same two `-e` flags, the same image and the same `storage/` volume. Changing `VULNGUARD_SECRET_KEY` **invalidates all JWT login sessions**. The printed row count must equal the number of credentials holding a secret. If interrupted, restore the step-1 backup.
6. Set `VULNGUARD_SECRET_KEY=<new>` permanently (or write the new key to `storage/secret.key`, mode `0600`). **Keep** `…_PREVIOUS` until verified.
7. Start. Verify: log in, **Test** several personal keys and the org key, run a small AI scan. There must be no `không giải mã được credential` log lines.
8. Re-enter the shared-box secrets. After an observation period (e.g. 7 days) remove `…_PREVIOUS` and destroy the old key per policy — **keep the old DB backup paired with the old key** if you may need to roll back, stored apart (section 0).

Rollback: stop, restore `storage/` from step 1, restore the old `VULNGUARD_SECRET_KEY`, drop `…_PREVIOUS`.

### 3. Residual risks (LOW, #109)

- **Whole-row restore**: a DB writer can put back an entire old `ai_credentials` row with its old `secret_enc`. The envelope binds id/owner/provider/`secret_gen`/params but cannot stop an exact rollback if the old key is still live at the provider. Mitigate: disable the old key at the provider on rotation; DB write access for the app only; keep backups apart.
- **Log masking**: the log scrubber scans 32 KB chunks; a key straddling a chunk boundary can leave a prefix (~22 chars of an `sk-proj-…` key). Never enable SDK DEBUG logging in production (the app refuses to start when `ANTHROPIC_LOG`/`OPENAI_LOG` is debug). Treat logs as sensitive.
- The scrubber may **over-mask** some long mixed-case identifiers (logs only).
- Co-work egress redaction misses exotic variants (`docker -p'X'`, `npm config set _password X`); every `exec` still needs user approval.
