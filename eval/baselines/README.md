# Capability baselines (P1-7)

`legacy.jsonl` — one JSON line per capability run of the `legacy` (single-agent) architecture with the D1 models.
Produced by `python -m eval.harness.capability --append-baseline` (nightly job `pentest-capability`, or manual).
Lines are reviewed and committed **manually by the owner**; CI never writes to the repository.

Run locally (real LLM, local lab only, hard cap 25 USD):

    export ANTHROPIC_API_KEY=...            # read ONLY by the llm-relay container
    python -m eval.harness.xbow              # build 3 XBOW benchmarks (pinned SHA, random flags)
    docker compose -f eval/lab/docker-compose.lab.yml -f eval/lab/docker-compose.capability.yml --profile capability up -d --no-build vg-under-test capture   # relay do harness khởi động (có token)
    python -m eval.harness.capability --profile opus --budget 25 --append-baseline

Safety metrics (`scope_violations`, `unapproved_intrusive`) must stay 0; the command exits non-zero otherwise.

## Real-LLM bench (P2-15b) — `pentest-bench`

Workflow `.github/workflows/pentest-bench.yml`: `bench-scripted` (PR + nightly, no LLM) and, for the real LLM, `preflight` → `bench-real` (matrix `legacy`/`graph`) → `bench-compare`.

**Setup (owner, once).** Add `ANTHROPIC_API_KEY` to the GitHub environment **`pentest-eval`** (Settings → Environments), with **deployment branches = `main` only** and **no required reviewers** (reviewers would make the weekly job wait for approval). Use a dedicated Anthropic workspace key with a workspace spend limit ≥ the run cap (25 USD) as a second safety net. Until the secret exists the workflow stays green: `preflight` writes *"skipped: ANTHROPIC_API_KEY is not set in environment pentest-eval"* and the other two jobs are skipped.

**Cost / cadence (O1).** Weekly (`45 18 * * 0`, Mon 01:45 ICT) + manual `workflow_dispatch` (inputs: suite, arch, k, budget, profile). Hard cap **25 USD per run, total across both arms** (each arm gets half; the relay meter is the source of truth and returns 402 at the cap). ≈ 100 USD/month at weekly cadence; switching to nightly is one cron line (owner decision — up to ~750 USD/month).

**Reading `bench-compare`.** The job summary shows per-task flags/tokens/USD for legacy vs graph and the 9b acceptance line (informational): `flags_graph ≥ flags_legacy`, billed-equivalent `tokens/flag` graph ÷ legacy ≤ 0.60, `safety == 0`. Only a safety metric > 0 fails a job. Two consecutive passing runs satisfy D3's switch-over condition; the owner decides.

**Trend (O7).** Each run appends both reports to `trend/bench-real.jsonl` in the `bench-trend` artifact (90-day retention); the next run downloads the previous one. No CI write access to the repo.

**Promoting a run to a baseline (manual).** Download the `bench-real-legacy` artifact, review `results/<suite>.jsonl`, and append the line you accept to `eval/baselines/legacy.jsonl` in a PR.

**Local, free: Ollama.** `make bench-local` runs the same bench on this machine against `qwen2.5:7b` (0 USD, tokens still counted) through the relay — see `docs/PENTEST_AGENT.md § Real-LLM bench`. It is never run in CI.
