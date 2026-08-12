"""Pipeline Intent Contract.

Freezes what a CI pipeline may read/write, which secrets it may consume, which
environments it may target, and which permissions each job may hold. Actual
pipeline jobs are compared against that intent; any expansion fails closed.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class PipelineIntentContractRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 1.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class PipelineIntentContractReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest, "metrics": self.metrics}


class PipelineIntentError(ValueError):
    pass


class PipelineIntentContract:
    MIN_BUDGET = 0.0

    @staticmethod
    def _strings(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
        if not isinstance(value, list):
            raise PipelineIntentError(f"{label}_not_list")
        rows = sorted({str(v).strip() for v in value if str(v).strip()})
        if not rows and not allow_empty:
            raise PipelineIntentError(f"{label}_missing")
        return rows

    @staticmethod
    def _id(value: Any, label: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise PipelineIntentError(f"{label}_missing")
        return value

    @classmethod
    def _contract(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise PipelineIntentError("intent_contract_missing")
        jobs_raw = raw.get("jobs")
        if not isinstance(jobs_raw, list) or not jobs_raw:
            raise PipelineIntentError("intent_jobs_missing")
        jobs: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(jobs_raw):
            if not isinstance(item, dict):
                raise PipelineIntentError(f"intent_job_{index}_not_object")
            job_id = cls._id(item.get("job_id"), f"intent_job_{index}_id")
            if job_id in jobs:
                raise PipelineIntentError(f"duplicate_intent_job:{job_id}")
            jobs[job_id] = {
                "job_id": job_id,
                "path_patterns": cls._strings(item.get("path_patterns", []), f"intent_job_{index}_path_patterns"),
                "secrets": cls._strings(item.get("secrets", []), f"intent_job_{index}_secrets"),
                "environments": cls._strings(item.get("environments", []), f"intent_job_{index}_environments"),
                "permissions": cls._strings(item.get("permissions", []), f"intent_job_{index}_permissions"),
                "required_dependencies": cls._strings(item.get("required_dependencies", []), f"intent_job_{index}_dependencies"),
            }
        return {
            "objective": cls._id(raw.get("objective"), "intent_objective"),
            "jobs": jobs,
            "forbidden_paths": cls._strings(raw.get("forbidden_paths", []), "forbidden_paths"),
            "forbidden_secrets": cls._strings(raw.get("forbidden_secrets", []), "forbidden_secrets"),
            "protected_environments": cls._strings(raw.get("protected_environments", []), "protected_environments"),
        }

    @classmethod
    def _actual_jobs(cls, raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list) or not raw:
            raise PipelineIntentError("actual_jobs_missing")
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise PipelineIntentError(f"actual_job_{index}_not_object")
            job_id = cls._id(item.get("job_id"), f"actual_job_{index}_id")
            if job_id in seen:
                raise PipelineIntentError(f"duplicate_actual_job:{job_id}")
            seen.add(job_id)
            rows.append({
                "job_id": job_id,
                "paths": cls._strings(item.get("paths", []), f"actual_job_{index}_paths"),
                "secrets": cls._strings(item.get("secrets", []), f"actual_job_{index}_secrets"),
                "environment": str(item.get("environment") or "").strip() or None,
                "permissions": cls._strings(item.get("permissions", []), f"actual_job_{index}_permissions"),
                "completed_dependencies": cls._strings(item.get("completed_dependencies", []), f"actual_job_{index}_completed_dependencies"),
            })
        return rows

    @staticmethod
    def _path_allowed(path: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)

    def evaluate(self, req: PipelineIntentContractRequest) -> PipelineIntentContractReceipt:
        reasons: list[str] = []
        if not str(req.subject_id or "").strip():
            reasons.append("subject_id_missing")
        if isinstance(req.budget, bool) or not isinstance(req.budget, (int, float)) or not math.isfinite(float(req.budget)) or float(req.budget) <= self.MIN_BUDGET:
            reasons.append("budget_non_positive_or_invalid")
        payload = req.payload if isinstance(req.payload, dict) else {}
        if not isinstance(req.payload, dict):
            reasons.append("payload_not_object")
        findings: list[dict[str, Any]] = []
        result = None
        try:
            contract = self._contract(payload.get("intent_contract"))
            jobs = self._actual_jobs(payload.get("actual_jobs"))
            protected_approvals = set(self._strings(payload.get("protected_environment_approvals", []), "protected_environment_approvals"))
            for job in jobs:
                expected = contract["jobs"].get(job["job_id"])
                if expected is None:
                    findings.append({"kind": "job_outside_intent", "job_id": job["job_id"]})
                    continue
                for path in job["paths"]:
                    if any(fnmatch.fnmatchcase(path, p) for p in contract["forbidden_paths"]):
                        findings.append({"kind": "forbidden_path_touched", "job_id": job["job_id"], "path": path})
                    elif expected["path_patterns"] and not self._path_allowed(path, expected["path_patterns"]):
                        findings.append({"kind": "path_outside_job_intent", "job_id": job["job_id"], "path": path})
                secret_expansion = set(job["secrets"]) - set(expected["secrets"])
                forbidden_secret_use = set(job["secrets"]) & set(contract["forbidden_secrets"])
                if secret_expansion:
                    findings.append({"kind": "secret_scope_expanded", "job_id": job["job_id"], "secrets": sorted(secret_expansion)})
                if forbidden_secret_use:
                    findings.append({"kind": "forbidden_secret_used", "job_id": job["job_id"], "secrets": sorted(forbidden_secret_use)})
                permission_expansion = set(job["permissions"]) - set(expected["permissions"])
                if permission_expansion:
                    findings.append({"kind": "permission_scope_expanded", "job_id": job["job_id"], "permissions": sorted(permission_expansion)})
                if job["environment"]:
                    if job["environment"] not in expected["environments"]:
                        findings.append({"kind": "environment_outside_intent", "job_id": job["job_id"], "environment": job["environment"]})
                    if job["environment"] in contract["protected_environments"] and job["environment"] not in protected_approvals:
                        findings.append({"kind": "protected_environment_approval_missing", "job_id": job["job_id"], "environment": job["environment"]})
                missing_deps = set(expected["required_dependencies"]) - set(job["completed_dependencies"])
                if missing_deps:
                    findings.append({"kind": "pipeline_dependency_not_satisfied", "job_id": job["job_id"], "dependencies": sorted(missing_deps)})
            result = {
                "aligned": not findings,
                "objective": contract["objective"],
                "findings": findings,
                "intent_digest": _digest(contract),
                "pipeline_digest": _digest(jobs),
            }
            if findings:
                reasons.append("pipeline_intent_drift_detected")
        except PipelineIntentError as exc:
            reasons.append(str(exc))
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        metrics = {"result": result, "finding_count": len(findings)}
        body = {"subject_id": req.subject_id, "decision": decision.value, "reasons": reasons, "metrics": metrics}
        return PipelineIntentContractReceipt(decision, tuple(reasons or ["pipeline_matches_frozen_intent"]), _digest(body), metrics)


Mechanism = PipelineIntentContract
