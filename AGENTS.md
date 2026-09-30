# AGENTS.md — gitlab-pipeline-intent-contract

**Company:** Gitlab
**Domain:** Enterprise Data Platform & Authority Governance

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/gitlab_pipeline_intent_contract/core.py` — Domain logic (Enterprise Data Platform & Authority Governance)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
