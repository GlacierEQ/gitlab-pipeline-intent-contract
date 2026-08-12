#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pipeline_intent_contract import Decision, PipelineIntentContract, PipelineIntentContractRequest


def _intent() -> dict:
    return {
        "project_id": "glaciereq/demo",
        "allowed_environments": ["test", "staging"],
        "read_paths": ["src/**", "tests/**"],
        "write_paths": ["dist/**", "reports/**"],
        "allowed_secrets": ["PACKAGE_TOKEN"],
    }


def _plan() -> list[dict]:
    return [
        {
            "job_id": "test",
            "environment": "test",
            "reads": ["src/app.py", "tests/test_app.py"],
            "writes": ["reports/junit.xml"],
            "secrets": [],
        },
        {
            "job_id": "package",
            "environment": "staging",
            "reads": ["src/app.py"],
            "writes": ["dist/app.whl"],
            "secrets": ["PACKAGE_TOKEN"],
        },
    ]


def main() -> int:
    engine = PipelineIntentContract()
    compiled = engine.evaluate(
        PipelineIntentContractRequest(
            "operate-demo", {"mode": "compile", "intent": _intent()}, budget=4.0
        )
    )
    if compiled.decision is not Decision.ALLOW:
        print(json.dumps(compiled.as_dict(), indent=2, sort_keys=True))
        return 2
    contract_digest = compiled.result["contract"]["contract_digest"]

    verified = engine.evaluate(
        PipelineIntentContractRequest(
            "operate-demo",
            {
                "mode": "verify",
                "intent": _intent(),
                "expected_contract_digest": contract_digest,
                "execution_plan": _plan(),
            },
            budget=4.0,
        )
    )

    drift_plan = _plan()
    drift_plan[0]["reads"].append("private/customer.db")
    drift_plan[0]["secrets"].append("ROOT_TOKEN")
    drift = engine.evaluate(
        PipelineIntentContractRequest(
            "operate-demo",
            {
                "mode": "verify",
                "intent": _intent(),
                "expected_contract_digest": contract_digest,
                "execution_plan": drift_plan,
            },
            budget=4.0,
        )
    )

    changed_intent = deepcopy(_intent())
    changed_intent["allowed_secrets"].append("ROOT_TOKEN")
    contract_mutation = engine.evaluate(
        PipelineIntentContractRequest(
            "operate-demo",
            {
                "mode": "verify",
                "intent": changed_intent,
                "expected_contract_digest": contract_digest,
                "execution_plan": _plan(),
            },
            budget=4.0,
        )
    )

    print(
        json.dumps(
            {
                "compiled": compiled.as_dict(),
                "verified": verified.as_dict(),
                "execution_drift": drift.as_dict(),
                "contract_mutation": contract_mutation.as_dict(),
            },
            indent=2,
            sort_keys=True,
        )
    )

    if verified.decision is not Decision.ALLOW:
        return 3
    if drift.decision is not Decision.REFUSE or "pipeline_intent_drift" not in drift.reasons:
        return 4
    if contract_mutation.decision is not Decision.REFUSE or "expected_contract_digest_mismatch" not in contract_mutation.reasons:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
