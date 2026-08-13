# Pipeline Intent Contract

A vendor-neutral content-addressed contract for freezing what a CI pipeline is intended to touch and refusing execution-plan drift.

> Independent GlacierEQ implementation. Not affiliated with, endorsed by, employed by, or deployed at GitLab.

## Purpose

CI pipelines routinely accumulate access to more environments, paths, and secrets than their original purpose requires. A green pipeline does not prove that the jobs still match the authority that was intended.

Pipeline Intent Contract separates those concerns into two explicit stages:

1. **compile** normalized intent into a stable `contract_digest`
2. **verify** a concrete execution plan against that frozen intent and return structured drift violations

## Intent model

A contract declares:

- `project_id`
- allowed environments
- readable path patterns
- writable path patterns
- allowed secret names

Lists are normalized and sorted before hashing, so equivalent intent produces the same contract digest regardless of input ordering.

## Verification model

Each planned job declares:

- unique `job_id`
- target environment
- concrete read paths
- concrete write paths
- secret names

Verification refuses and reports structured violations for:

- environment expansion
- undeclared read paths
- undeclared write paths
- undeclared secrets
- duplicate jobs
- malformed or unknown fields
- absolute, traversal, Windows-style, or globbed concrete paths
- request expiry
- oversized plans or evaluation work beyond the declared budget

`expected_contract_digest` can bind verification to a previously retained intent identity. If the contract itself changes, verification refuses before silently accepting the broader authority.

The inherited request `grant_id`, when present, is validated and carried as an opaque `grant_reference` in the receipt. It is **not** treated as proof of authorization by this package.

## Example

```json
{
  "subject_id": "pipeline-42",
  "budget": 4.0,
  "payload": {
    "mode": "verify",
    "intent": {
      "project_id": "glaciereq/app",
      "allowed_environments": ["test", "staging"],
      "read_paths": ["src/**", "tests/**"],
      "write_paths": ["dist/**", "reports/**"],
      "allowed_secrets": ["PACKAGE_TOKEN"]
    },
    "execution_plan": [
      {
        "job_id": "test",
        "environment": "test",
        "reads": ["src/app.py", "tests/test_app.py"],
        "writes": ["reports/junit.xml"],
        "secrets": []
      }
    ]
  }
}
```

## Install and run

```bash
python -m pip install .
pipeline-intent-contract --input request.json
```

Exit status is zero only when compilation/verification succeeds. Refused verification returns the normalized contract, plan where safe to compute it, and structured violations.

## Verify this repository

```bash
python -m pytest -q
python scripts/operate.py
```

The direct runtime smoke compiles intent, verifies a matching plan, refuses path/secret expansion, and refuses a mutated contract when checked against the original digest.

## Integration boundary

This package does not pretend to be a GitLab API client or a full `.gitlab-ci.yml` interpreter. A real GitLab adapter can resolve includes/rules and map the resulting planned jobs, environments, file effects, and secret references into this normalized contract. The contract engine then owns deterministic intent identity and drift verification, while provider authentication and pipeline execution remain with the system that actually performs them.
