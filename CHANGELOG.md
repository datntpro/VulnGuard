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
