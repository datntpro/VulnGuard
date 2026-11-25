# Changelog

## Unreleased

### Security — Docker hardening, supply chain, lockfiles (PR-H; N-5, N-9, L-5, B-6) (BREAKING for local-image scans / dependency workflow)
- **N-5 / D-4:** `docker.sock` is no longer mounted into the app (a `:ro` socket mount still accepts `POST /containers/create` with `Privileged`).
  New `docker-compose.local-images.yml` routes `DOCKER_HOST` through a pinned, read-only `docker-socket-proxy` (`POST=0`, images/ping/version only; port not published).
  **Breaking:** scanning images that exist only in the local daemon now requires `-f docker-compose.local-images.yml`; public images are unaffected.
- **N-9:** compose hint is now `sudo chown -R 10001:10001 storage` (no `chmod 777`); new `api/docker-entrypoint.sh` fails fast with that hint when `/app/storage/db` is not writable.
- **L-5:** every downloaded binary (trivy, gitleaks, grype, hadolint, katana, nuclei, ffuf, sonar-scanner) is version-pinned and verified with per-arch `sha256`;
  no more `curl | sh` for grype; trivy comes from the release tarball (not the unpinned apt repo); SecLists pinned to a tag.
  Core scanners (trivy, gitleaks, grype, hadolint) now fail the image build on any error; only optional tools may be skipped.
- **B-6:** `api/requirements.in` → hash-locked `api/requirements.txt` (`uv pip compile --universal --generate-hashes`), installed once with `--require-hashes`.
  semgrep, bandit, checkov, pip-audit each get their own venv from `docker/scanners/<tool>.txt`; `detect-secrets` stays in the app env. `requirements-dev.txt` and `coworker_host/requirements.txt` are locked too.
  CI installs from the lock and runs `pip-audit` on it; `.github/dependabot.yml` added. Image smoke test now also runs `grype`, `hadolint` and `pip check`.
- Review follow-ups: `FORWARDED_ALLOW_IPS` is now passed through `docker-compose.yml` (`.env` setting works); `defusedxml` added to `requirements.in` + lock (PR #43 should drop its raw `requirements.txt` line); entrypoint also detects root-owned files inside storage (e.g. `db/vulnguard.db`) and derives the path from `DATABASE_URL`; `install/install.sh` installs semgrep/bandit/checkov/pip-audit into separate venvs from `docker/scanners/*.txt` (no more co-install into the app venv).
- Image: `FORWARDED_ALLOW_IPS=127.0.0.1` made explicit, uvicorn started with `--workers 1` (in-memory state; run.sh single-worker enforcement is in PR #42).

### Security — low-severity hardening (PR-I: L-6, B-5; L-4 is delivered by #37)
- Qualys/OpenVAS connectors parse XML with `defusedxml` (billion-laughs / entity expansion is rejected and the
  parser returns no results; Bandit B314 ×4 gone). `defusedxml` is pinned in `api/requirements.in` + the hash lock (PR-H).
- **BREAKING:** VulnGuard supports a single worker. `run.sh`, `install/run.sh` and the systemd unit force `--workers 1`;
  `VULNGUARD_WORKERS>1` is ignored with a warning (in-memory scan locks, proxy registry, scheduler, lockout, Co-work nonces).
- **BREAKING:** native `scripts/setup.py` now binds `VULNGUARD_BIND` (default `127.0.0.1`, was `0.0.0.0`); the systemd
  template binds `127.0.0.1`. `run.sh`/`setup.py`/`install/run.sh` refuse to start with `AUTH_ENABLED=false` and a non-loopback host.
- **LAN access (opt-in, documented):** one variable `VULNGUARD_BIND` (default `127.0.0.1`) now controls the bind for Docker compose
  *and* native `run.sh`/`run.ps1`/`install/run.sh`/`setup.py`; `VULNGUARD_HOST` stays as a deprecated alias (warning). The app and every
  launcher refuse to start on a non-loopback bind with `AUTH_ENABLED=false`. Startup logs warn on LAN bind without `ALLOWED_HOSTS` /
  with plain-HTTP cookies. The pentest MITM proxy port has its own `PENTEST_PROXY_BIND` (default loopback) so opening the UI does not
  expose it; optional `docker-compose.lan.yml`. Compose now passes `AUTH_ENABLED`, `ALLOWED_HOSTS`, `COOKIE_SECURE`, `CORS_ALLOW_ORIGINS`,
  `VULNGUARD_SECRET_KEY`, `SESSION_TTL_HOURS`, `EXPOSE_API_DOCS`, `SCM_*` into the container (previously `.env` had no effect there).
  `run_demo.sh` now binds loopback by default. New wiki page "Truy cập từ máy khác trong LAN" (incl. Caddy TLS), fixes wrong Installation.md.
  The "anyone on the LAN can claim ADMIN via `/api/auth/setup`" gap is closed by the setup token in #42 (not duplicated here).
- Skipped on purpose: L-4 (pentest proxy auth, loopback default, CA lifetime) — already implemented in #37.

### Security — first-run setup token (L-2, BREAKING first-run UX) + single worker (D-14)
- `POST /api/auth/setup` now requires `setup_token`: `VULNGUARD_SETUP_TOKEN`, or an auto-generated `storage/setup_token`
  (0600, created only while no user exists, deleted after a successful setup; never logged — only its path). Wrong/missing
  token → 403, repeated guesses → 429 (shared lockout limiter). `/api/auth/status` adds `setup_token_required`.
- Login page setup form has a "Setup token" field. `scripts/bootstrap_admin.py` (installer) is unchanged.
- `run.sh` ignores `VULNGUARD_WORKERS>1` with a warning (in-memory state requires a single worker).
- Tests: `tests/test_setup_token.py`.

### Fixed — first-login change-password UX (BREAKING for API clients)
- `POST /api/auth/change-password` now requires `confirm_password` (must equal `new_password`, else 422, nothing written)
  and enforces a password policy (10–200 chars, ≥3 of 4 character classes, not containing the email local part,
  not a single repeated character). The same policy applies to `/setup`, `POST /users` and `PATCH /users/{id}`.
- After a change the response returns a fresh session; all other sessions/tokens are revoked (`token_version`). Failed-login
  lockout for the account is cleared.
- Web UI: forced-change dialog has new + confirm fields, strength meter, rule text, show/hide; reloads after success so the
  stale "must change password" errors disappear.
- Tests: `tests/test_change_password.py` (API) and `tests/test_ui_change_password.py` (headless Chromium, runs in CI).


### Security — path allow-lists, zip bomb, File Assistant (fix/path-policy)
- **M-3** `scan_path` must resolve (realpath, so symlinks and `..` cannot escape) under an allowed root for every role. New `api/services/path_policy.py`; roots from `SCAN_ALLOWED_ROOTS`, default `/workspace` (Docker) or the user's home (native), plus `storage/scan_uploads`. The app storage directory (DB, `secret.key`) is always refused. Violations return 400.
- **H-1** File Assistant file paths are validated against `FILE_ASSISTANT_ALLOWED_ROOTS` (default: scan roots) at session creation (client `size_bytes` is ignored, max 20 MiB) and re-validated before every read, so legacy sessions or swapped symlinks are rejected.
- **M-5** Zip uploads are streamed to a temp file (413 above `UPLOAD_MAX_BYTES`) and extracted with limits on file count, total uncompressed size, compression ratio and actual bytes written per member (lying headers abort), plus a free-disk check. Failed extractions are removed; rotating out an old upload scan deletes its directory.
- **B-4** File Assistant health uses `text("SELECT 1")` (database check was always false) and really probes the Coworker Host.

### PR #32 verification fixes
- Deny-list (app storage, credential dirs) is compared casefold + NFC on both the raw and resolved path, so `STORAGE`/`.DOCKER` on case-insensitive APFS no longer bypass it.
- Credential deny-list for scan and File Assistant: `~/.ssh`, `.gnupg`, `.aws`, `.azure`, `.config`, `.docker`, `.kube`, `.local`, `Library`, `.netrc`, `.npmrc`, `.pypirc`, git credentials; files `.env*`, `*.pem`, `*.key`, `*.p12`, keychains, `id_*`, the app `.env`. Scanning a directory that contains such a folder (e.g. `~` itself) is refused: pick the project folder.
- `storage/scan_uploads` is no longer a selectable root (cross-project read); rotation only deletes `scan_uploads/<own project>/<hex>`, never a RUNNING scan or a path another scan still references.
- Relative `scan_path` is rejected; relative or missing configured roots are ignored with a warning.
- Zip: End-of-Central-Directory entry count / size is checked before `zipfile` parses the directory; `Content-Length` (or streamed bytes) over `UPLOAD_MAX_BYTES` + 1 MiB is rejected with 413 by a middleware before Starlette spools the body.
- File Assistant re-checks the file extension on the resolved path.

### PR #32 re-verification fixes
- Credential deny-list is now a blanket rule: every top-level dot entry under `$HOME` (`~/.*`, casefold + NFC) plus `~/Library` is refused for both scan and File Assistant, and `~` itself (or an ancestor) cannot be scanned. A project placed under a dot directory of home (or `SCAN_ALLOWED_ROOTS` pointing into one) is therefore refused too. macOS firmlink aliases (`/System/Volumes/Data/...`) are normalised.
- Zip pre-check no longer trusts EOCD counts: it locates the central directory the way CPython does (always probing the Zip64 locator) and counts records without building `ZipInfo`, aborting past `UPLOAD_MAX_FILES`.
- A chunked upload over the limit now returns a real 413. Every POST/PUT/PATCH body is bounded (`BODY_MAX_BYTES`, default 300 MiB; `/scan-upload` uses `UPLOAD_MAX_BYTES`).

### Breaking changes (path-policy)
- Scanning `~` itself, or any directory containing a credential folder, is refused in native mode.
- **D-7** Scans of paths outside the allowed roots are now refused (400), for all roles. Set `SCAN_ALLOWED_ROOTS` to widen. Existing scans are unaffected.
- **D-8** `FEATURE_FILE_ASSISTANT` now defaults to `false` (module returns 404) until its UI exists; set it to `true` to use the API.
- Known residual: a directory swapped for a symlink between validation and scan (TOCTOU) is not prevented.

### Security — Coworker Host exec policy (BREAKING)
- `COWORKER_EXEC_MODE` (`safe` default / `trusted` / `off`). In `safe`, Co-work can no longer run
  `python3`, `pytest`, `npm`, `make`, `go`, `cargo`... Set `COWORKER_EXEC_MODE=trusted` on the host to opt in
  (each non-read command then needs a server-issued, single-use `confirm_id`; the old `confirm: true` flag is ignored).
- Command arguments are confined to the granted folder; `find -exec`, `grep -R`, `tail -f`, `git -c ...` etc. are rejected.
  Only bare command names are accepted (no `./cat`, `/bin/cat`).
- `PUT /whitelist` only accepts read-only commands; stored whitelists are intersected with them.
- Folder grants for `~/.ssh`, `~/Library`, `/etc`, ancestors of `$HOME`, or the coworker data dir are refused
  (also enforced at use time for existing grants). Optional `COWORKER_ALLOWED_ROOTS`.
- Writes into `.git/.husky/.vscode/.idea/.direnv/.envrc` and the coworker data dir are refused.
- Host header parsing handles IPv6 (`[::1]:8765`); an empty Host is rejected (421).
- The auto-generated token is no longer logged (only its file path). `coworker_host/run.sh` no longer sources `.env`.
- Scanner subprocesses no longer inherit `VULNGUARD_COWORKER_TOKEN`, API keys or cloud secrets.
- Hardening after independent adversarial review: all path policies (folder grants, write denylist, DATA_DIR,
  `COWORKER_ALLOWED_ROOTS`) compare case-insensitively (`~/.SSH`, `/USERS/x`, `.GIT/config` on APFS/NTFS);
  git runs with `--attr-source=<empty tree>` (needs git >= 2.40) so `filter`/`textconv` drivers from `.gitattributes`
  cannot execute; safe-mode `git branch` is list-only; `git blame --contents`, `--no-index`, `--ignore-revs-file`,
  `-O` are denied and every git path-like value is confined; `find` global flags (`-H -L -f -P -x ...`) are parsed
  before confinement; `grep`/`tail`/`tree`/`ls` short-option clusters (`-rf`, `-fPATH`, `-rS`, `-lH`) are parsed
  getopt-style; writes to `.gitattributes`/`.gitmodules` are refused; child stdin is `/dev/null`; bracketed Host
  headers must be well-formed (`[::1]evil` -> 421).
- Second review round: git runs with `GIT_CEILING_DIRECTORIES=<parent of root>` and a pre-flight that refuses (403)
  when the repo's toplevel / git-dir / common-dir resolve outside the granted root (dotfiles repo at `$HOME`,
  `.git` file with `gitdir:` outside, `core.worktree` outside; legitimate `git worktree` checkouts whose gitdir is
  outside the root are therefore refused) or when `.git/info/attributes` defines attributes (hostile-repo filter/textconv).
  `find` parses BSD flag clusters (`-xL`, `-Ef`, `-sx`) and `--`; `diff -r/--recursive` is denied (Apple diff follows
  symlinks while recursing) and attached `-X<file>` is confined; Host ports must be numeric.
- Third review round: `find -f<path>` (attached value) denied; `diff` operands must not be directories (Apple diff follows
  symlinked entries one level down); safe-mode `git diff`/`git status` run with `--ignore-submodules=all`
  (+ `diff.submodule=short`, `status.submoduleSummary=false`) and `--submodule*`/`--ignore-submodules*` are denied, so a hostile
  submodule gitdir cannot run its filters (side effect: dirty submodules are not shown); repos whose
  `objects/info/alternates` point outside the granted root are refused. Linked `git worktree` checkouts with the gitdir
  outside the root remain unsupported (fail-closed).

### Security — auth-off, CORS/CSRF, RBAC, docs, headers (fix/authoff-cors-rbac)
- **M-2** `AUTH_ENABLED=false` no longer exposes admin power: admin-only routes, `/api/coworker` and `/api/file-assistant` return 403 (`auth_required`); the dev pseudo-user is ANALYST; Host must be loopback (or `ALLOWED_HOSTS`) → 421 (DNS rebinding); the File Assistant WebSocket refuses when auth is off. CORS `*` removed (same-origin only unless `CORS_ALLOW_ORIGINS`). New Origin/`Sec-Fetch-Site` guard rejects cross-site writes (`bad_origin`) with auth on or off.
- **L-1** `ADMIN_ONLY` now covers `POST/DELETE /api/settings/*` (logo, SonarQube/SMTP test), `POST/DELETE /api/scm/connections`, `GET /api/scm/connections/{id}/…`, `POST /api/ai/test`. SCM `base_url` is SSRF-checked (https only, no loopback/link-local/metadata; private ranges allowed by default) at create, validate, list and clone time.
- **L-3 / D-11** `must_change_password` is enforced by the API (403 `must_change_password`), not only the UI; users created by an admin and admin password resets set the flag. Fixed a latent bug where `POST /api/auth/change-password` modified a detached user object and never persisted.
- **I-1** `/docs`, `/redoc`, `/openapi.json` require login; `EXPOSE_API_DOCS=false` disables them. `mask_secret` shows only `…` + last 4 chars.
- **E.5** Security headers on every response (`nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`) and a baseline CSP on HTML pages (Google Fonts allowed for `brand.css`).

#### Review follow-ups (PR-E)
- VIEWER accounts forced to change their password can now call `change-password`, `logout` and `logout-all` (previously permanently locked out).
- `must_change_password` is also enforced on the File Assistant WebSocket.
- `POST /api/auth/setup` returns 403 when `AUTH_ENABLED=false` (cannot plant the first ADMIN).
- SCM `git clone` no longer follows HTTP redirects and only allows https (http with `SCM_ALLOW_HTTP`).
- `check_base_url`: blocks `100.100.100.200`, `192.0.0.192`, IPv6-embedded IPv4 (6to4/NAT64/Teredo); with `SCM_ALLOW_PRIVATE_HOSTS=false` requires a globally routable address.

#### Breaking changes (PR-E)
- Third-party browser clients of the API break unless listed in `CORS_ALLOW_ORIGINS`. The bundled UI is unaffected.
- With `AUTH_ENABLED=false`, Co-work, File Assistant and all admin routes are unavailable; requests with a non-loopback `Host` get 421.
- Newly created users and admin-reset passwords must change the password before using the API.
- `/docs`, `/redoc`, `/openapi.json` need a session; masked key hints now show only the last 4 characters.
- ANALYST/VIEWER can no longer call the SCM connection management, settings sub-endpoints or `/api/ai/test`.

### Security — session revocation (fix/session-revocation)
- **N-1** `POST /api/auth/logout` now actually revokes the JWT (per-token `jti` denylist, table `revoked_tokens`, created automatically). Previously the endpoint was public, the revoke branch never ran and the token stayed valid for `SESSION_TTL_HOURS`.
- **N-2/M-4** File Assistant WebSocket validates the real session (revocation, `token_version`, `is_active`, current role) before `accept()` and on every message; rejects cross-origin handshakes and honours `FEATURE_FILE_ASSISTANT`.
- **N-3** Login lockout no longer locks out the legitimate user: buckets by a signed per-device cookie (`vg_device`) when present, otherwise one shared untrusted bucket per email; bounded store; `Retry-After` header.

### Hardening after independent verification
- Device cookie MAC is now unambiguous (length-prefixed, derived subkey, bound to the user id, strict nonce format); an email containing `|` can no longer mint trusted buckets for another account.
- Lockout check + attempt increment is atomic and happens before the scrypt verification, so concurrent guesses cannot exceed 5.
- Untrusted clients share one bucket per email (not per IP); locked buckets are not evicted when the store is full.
- Unknown-email logins verify against a precomputed dummy hash (equal timing); logout falls back to the cookie token when the `Authorization` header token is invalid.

### Breaking changes
- Rotating `VULNGUARD_SECRET_KEY` invalidates all `vg_device` cookies. Clients without the cookie (CLI/CI) can still be locked for 15 minutes by anyone who can reach the login endpoint.
- Logout now revokes **only the current token** (decision D-1). Other sessions / CLI tokens of the same user keep working. Use the new `POST /api/auth/logout-all` to end every session of a user.
- JWTs now carry a `jti` claim. Tokens issued before this release (no `jti`) are revoked on logout by bumping `token_version`, which ends all sessions of that user.
- WebSocket clients sending an `Origin` that differs from `Host` are refused.
