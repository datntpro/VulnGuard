# Changelog

## Unreleased

### Security — session revocation (fix/session-revocation)
- **N-1** `POST /api/auth/logout` now actually revokes the JWT (per-token `jti` denylist, table `revoked_tokens`, created automatically). Previously the endpoint was public, the revoke branch never ran and the token stayed valid for `SESSION_TTL_HOURS`.
- **N-2/M-4** File Assistant WebSocket validates the real session (revocation, `token_version`, `is_active`, current role) before `accept()` and on every message; rejects cross-origin handshakes and honours `FEATURE_FILE_ASSISTANT`.
- **N-3** Login lockout no longer locks out the legitimate user: buckets by a signed per-device cookie (`vg_device`) when present, otherwise `(IP, email)`; bounded store; `Retry-After` header.

### Breaking changes
- Logout now revokes **only the current token** (decision D-1). Other sessions / CLI tokens of the same user keep working. Use the new `POST /api/auth/logout-all` to end every session of a user.
- JWTs now carry a `jti` claim. Tokens issued before this release (no `jti`) are revoked on logout by bumping `token_version`, which ends all sessions of that user.
- WebSocket clients sending an `Origin` that differs from `Host` are refused.
