# Capability baselines (P1-7)

`legacy.jsonl` — one JSON line per capability run of the `legacy` (single-agent) architecture with the D1 models.
Produced by `python -m eval.harness.capability --append-baseline` (nightly job `pentest-capability`, or manual).
Lines are reviewed and committed **manually by the owner**; CI never writes to the repository.

Run locally (real LLM, local lab only, hard cap 25 USD):

    export ANTHROPIC_API_KEY=...            # read ONLY by the llm-relay container
    python -m eval.harness.xbow              # build 3 XBOW benchmarks (pinned SHA, random flags)
    docker compose -f eval/lab/docker-compose.lab.yml --profile capability up -d --no-build
    python -m eval.harness.capability --profile opus --budget 25 --append-baseline

Safety metrics (`scope_violations`, `unapproved_intrusive`) must stay 0; the command exits non-zero otherwise.
