# Changelog

## Unreleased

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
=======
### Security — auth-off, CORS/CSRF, RBAC, docs, headers (fix/authoff-cors-rbac)
- **M-2** `AUTH_ENABLED=false` no longer exposes admin power: admin-only routes, `/api/coworker` and `/api/file-assistant` return 403 (`auth_required`); the dev pseudo-user is ANALYST; Host must be loopback (or `ALLOWED_HOSTS`) → 421 (DNS rebinding); the File Assistant WebSocket refuses when auth is off. CORS `*` removed (same-origin only unless `CORS_ALLOW_ORIGINS`). New Origin/`Sec-Fetch-Site` guard rejects cross-site writes (`bad_origin`) with auth on or off.
- **L-1** `ADMIN_ONLY` now covers `POST/DELETE /api/settings/*` (logo, SonarQube/SMTP test), `POST/DELETE /api/scm/connections`, `GET /api/scm/connections/{id}/…`, `POST /api/ai/test`. SCM `base_url` is SSRF-checked (https only, no loopback/link-local/metadata; private ranges allowed by default) at create, validate, list and clone time.
- **L-3 / D-11** `must_change_password` is enforced by the API (403 `must_change_password`), not only the UI; users created by an admin and admin password resets set the flag. Fixed a latent bug where `POST /api/auth/change-password` modified a detached user object and never persisted.
- **I-1** `/docs`, `/redoc`, `/openapi.json` require login; `EXPOSE_API_DOCS=false` disables them. `mask_secret` shows only `…` + last 4 chars.
- **E.5** Security headers on every response (`nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`) and a baseline CSP on HTML pages (Google Fonts allowed for `brand.css`).

#### Breaking changes (PR-E)
- Third-party browser clients of the API break unless listed in `CORS_ALLOW_ORIGINS`. The bundled UI is unaffected.
- With `AUTH_ENABLED=false`, Co-work, File Assistant and all admin routes are unavailable; requests with a non-loopback `Host` get 421.
- Newly created users and admin-reset passwords must change the password before using the API.
- `/docs`, `/redoc`, `/openapi.json` need a session; masked key hints now show only the last 4 characters.
- ANALYST/VIEWER can no longer call the SCM connection management, settings sub-endpoints or `/api/ai/test`.
>>>>>>> 6098ffb (fix(E): auth-off lockdown, CORS/CSRF/Host guards, RBAC gaps + SCM SSRF, must-change-password, docs auth, security headers)

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
