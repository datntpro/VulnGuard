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
