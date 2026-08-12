from __future__ import annotations

from pipeline_intent_contract import Decision, PipelineIntentContract, PipelineIntentContractRequest


def contract():
    return {"objective":"build and deploy app without expanding CI authority","forbidden_paths":["secrets/**"],"forbidden_secrets":["ROOT_TOKEN"],"protected_environments":["production"],"jobs":[
        {"job_id":"test","path_patterns":["src/**","tests/**"],"secrets":[],"environments":[],"permissions":["repo.read"],"required_dependencies":[]},
        {"job_id":"deploy","path_patterns":["dist/**"],"secrets":["DEPLOY_TOKEN"],"environments":["production"],"permissions":["repo.read","deploy.write"],"required_dependencies":["test"]},
    ]}


def jobs():
    return [
        {"job_id":"test","paths":["src/app.py","tests/test_app.py"],"secrets":[],"environment":None,"permissions":["repo.read"],"completed_dependencies":[]},
        {"job_id":"deploy","paths":["dist/app.whl"],"secrets":["DEPLOY_TOKEN"],"environment":"production","permissions":["repo.read","deploy.write"],"completed_dependencies":["test"]},
    ]


def evaluate(actual=None, approvals=None):
    return PipelineIntentContract().evaluate(PipelineIntentContractRequest("pipeline-a",{"intent_contract":contract(),"actual_jobs":actual or jobs(),"protected_environment_approvals":["production"] if approvals is None else approvals},1.0))


def kinds(receipt):
    return {f["kind"] for f in receipt.metrics["result"]["findings"]}


def test_pipeline_matching_frozen_intent_passes() -> None:
    r=evaluate(); assert r.decision is Decision.ALLOW
    assert r.metrics["result"]["aligned"] is True
    assert len(r.metrics["result"]["intent_digest"])==64


def test_unknown_job_is_scope_expansion() -> None:
    rows=jobs()+[{"job_id":"admin","paths":[],"secrets":[],"environment":None,"permissions":[],"completed_dependencies":[]}]
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "job_outside_intent" in kinds(r)


def test_forbidden_path_is_refused() -> None:
    rows=jobs(); rows[0]["paths"].append("secrets/prod.env")
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "forbidden_path_touched" in kinds(r)


def test_path_outside_job_intent_is_refused() -> None:
    rows=jobs(); rows[0]["paths"].append("infra/main.tf")
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "path_outside_job_intent" in kinds(r)


def test_secret_scope_expansion_is_refused() -> None:
    rows=jobs(); rows[0]["secrets"]=["DEPLOY_TOKEN"]
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "secret_scope_expanded" in kinds(r)


def test_forbidden_root_secret_is_refused() -> None:
    rows=jobs(); rows[1]["secrets"].append("ROOT_TOKEN")
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "forbidden_secret_used" in kinds(r)


def test_permission_expansion_is_refused() -> None:
    rows=jobs(); rows[0]["permissions"].append("repo.admin")
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "permission_scope_expanded" in kinds(r)


def test_protected_environment_requires_explicit_approval() -> None:
    r=evaluate(approvals=[]); assert r.decision is Decision.REFUSE
    assert "protected_environment_approval_missing" in kinds(r)


def test_required_pipeline_dependency_must_be_satisfied() -> None:
    rows=jobs(); rows[1]["completed_dependencies"]=[]
    r=evaluate(rows); assert r.decision is Decision.REFUSE
    assert "pipeline_dependency_not_satisfied" in kinds(r)
