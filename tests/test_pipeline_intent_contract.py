from copy import deepcopy

from pipeline_intent_contract import (
    Decision,
    PipelineIntentContract,
    PipelineIntentContractRequest,
)


def intent() -> dict:
    return {
        "project_id": "glaciereq/app",
        "allowed_environments": ["test", "staging"],
        "read_paths": ["src/**", "tests/**", "pyproject.toml"],
        "write_paths": ["dist/**", "reports/**"],
        "allowed_secrets": ["PACKAGE_TOKEN", "STAGING_API_TOKEN"],
    }


def plan() -> list[dict]:
    return [
        {
            "job_id": "test",
            "environment": "test",
            "reads": ["src/app.py", "tests/test_app.py", "pyproject.toml"],
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


def evaluate(payload: dict, *, budget=4.0, not_after=None):
    return PipelineIntentContract().evaluate(
        PipelineIntentContractRequest(
            "pipeline-42",
            payload,
            budget=budget,
            not_after=not_after,
        )
    )


def test_compile_produces_stable_content_addressed_contract():
    first = evaluate({"mode": "compile", "intent": intent()})
    second_intent = intent()
    second_intent["allowed_environments"].reverse()
    second_intent["read_paths"].reverse()
    second = evaluate({"mode": "compile", "intent": second_intent})
    assert first.decision is Decision.ALLOW
    assert first.result["contract"]["contract_digest"] == second.result["contract"]["contract_digest"]
    assert first.result["contract"] == second.result["contract"]


def test_matching_plan_allows():
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": plan()})
    assert receipt.decision is Decision.ALLOW
    assert receipt.reasons == ("pipeline_plan_matches_frozen_intent",)
    assert receipt.metrics["violation_count"] == 0
    assert receipt.metrics["job_count"] == 2
    assert len(receipt.result["execution_plan_digest"]) == 64


def test_environment_drift_refuses():
    changed = plan()
    changed[1]["environment"] = "production"
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": changed})
    assert receipt.decision is Decision.REFUSE
    assert "pipeline_intent_drift" in receipt.reasons
    assert {v["kind"] for v in receipt.result["violations"]} == {"environment_drift"}


def test_read_write_and_secret_drift_are_reported_independently():
    changed = plan()
    changed[0]["reads"].append("private/customer.db")
    changed[0]["writes"].append("src/generated.py")
    changed[0]["secrets"].append("ROOT_TOKEN")
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": changed})
    assert receipt.decision is Decision.REFUSE
    kinds = {violation["kind"] for violation in receipt.result["violations"]}
    assert kinds == {"read_path_drift", "write_path_drift", "secret_drift"}


def test_expected_contract_digest_binds_frozen_intent():
    compiled = evaluate({"mode": "compile", "intent": intent()})
    digest = compiled.result["contract"]["contract_digest"]
    verified = evaluate(
        {
            "mode": "verify",
            "intent": intent(),
            "expected_contract_digest": digest,
            "execution_plan": plan(),
        }
    )
    assert verified.decision is Decision.ALLOW

    changed_intent = intent()
    changed_intent["allowed_secrets"].append("ROOT_TOKEN")
    refused = evaluate(
        {
            "mode": "verify",
            "intent": changed_intent,
            "expected_contract_digest": digest,
            "execution_plan": plan(),
        }
    )
    assert refused.decision is Decision.REFUSE
    assert "expected_contract_digest_mismatch" in refused.reasons


def test_path_traversal_and_windows_paths_are_refused_before_matching():
    traversal = plan()
    traversal[0]["reads"] = ["src/../secret.txt"]
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": traversal})
    assert receipt.decision is Decision.REFUSE
    assert "job_0_reads_0_invalid" in receipt.reasons

    windows = plan()
    windows[0]["reads"] = [r"src\app.py"]
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": windows})
    assert receipt.decision is Decision.REFUSE
    assert "job_0_reads_0_invalid" in receipt.reasons


def test_duplicate_job_ids_refuse():
    duplicate = plan()
    duplicate[1]["job_id"] = "test"
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": duplicate})
    assert receipt.decision is Decision.REFUSE
    assert "duplicate_job_id" in receipt.reasons


def test_unknown_intent_and_job_fields_fail_closed():
    changed_intent = intent()
    changed_intent["magic"] = True
    receipt = evaluate({"mode": "compile", "intent": changed_intent})
    assert receipt.decision is Decision.REFUSE
    assert "intent_keys_unknown:magic" in receipt.reasons

    changed_plan = plan()
    changed_plan[0]["sudo"] = True
    receipt = evaluate({"mode": "verify", "intent": intent(), "execution_plan": changed_plan})
    assert receipt.decision is Decision.REFUSE
    assert "job_0_keys_unknown:sudo" in receipt.reasons


def test_request_expiry_refuses():
    receipt = evaluate(
        {"mode": "verify", "now": 100.0, "intent": intent(), "execution_plan": plan()},
        not_after=99.0,
    )
    assert receipt.decision is Decision.REFUSE
    assert "request_expired" in receipt.reasons


def test_work_budget_is_enforced():
    expanded = deepcopy(plan())
    expanded[0]["reads"] = [f"src/file_{i}.py" for i in range(100)]
    receipt = evaluate(
        {"mode": "verify", "intent": intent(), "execution_plan": expanded},
        budget=0.6,
    )
    assert receipt.decision is Decision.REFUSE
    assert "work_budget_exceeded" in receipt.reasons


def test_subject_identity_is_strict():
    receipt = PipelineIntentContract().evaluate(
        PipelineIntentContractRequest(123, {"mode": "compile", "intent": intent()}, budget=4.0)  # type: ignore[arg-type]
    )
    assert receipt.decision is Decision.REFUSE
    assert "subject_id_type_invalid" in receipt.reasons
