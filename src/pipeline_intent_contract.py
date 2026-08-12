"""Content-addressed pipeline intent contracts and execution-plan drift checks."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import posixpath
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class PipelineIntentContractRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 4.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class PipelineIntentContractReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
            "result": self.result,
        }


class PipelineIntentContract:
    """Compile frozen intent and verify normalized CI execution plans against it."""

    MODES = frozenset({"compile", "verify"})
    VALID_PAYLOAD_KEYS = frozenset(
        {"mode", "now", "intent", "execution_plan", "expected_contract_digest"}
    )
    INTENT_KEYS = frozenset(
        {"project_id", "allowed_environments", "read_paths", "write_paths", "allowed_secrets"}
    )
    JOB_KEYS = frozenset(
        {"job_id", "environment", "reads", "writes", "secrets"}
    )
    MAX_JOBS = 256
    MAX_PATTERNS = 256
    MAX_SECRETS = 256
    MAX_ITEMS_PER_JOB = 256
    MAX_TEXT = 4096
    MAX_INPUT_CHARS = 2_000_000
    BASE_WORK = 0.5
    ITEM_WORK = 0.01

    @classmethod
    def _text(cls, value: Any, label: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{label}_type_invalid")
        value = value.strip()
        if not value:
            raise ValueError(f"{label}_missing")
        if len(value) > cls.MAX_TEXT:
            raise ValueError(f"{label}_too_long")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError(f"{label}_control_character")
        return value

    @staticmethod
    def _number(value: Any, label: str, *, minimum: float = 0.0) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label}_invalid")
        value = float(value)
        if not math.isfinite(value) or value < minimum:
            raise ValueError(f"{label}_invalid")
        return value

    @classmethod
    def _path(cls, value: Any, label: str, *, pattern: bool) -> str:
        value = cls._text(value, label)
        if value.startswith("/") or "\\" in value:
            raise ValueError(f"{label}_invalid")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"{label}_invalid")
        if not pattern and any(ch in value for ch in "*?["):
            raise ValueError(f"{label}_glob_not_allowed")
        normalized = posixpath.normpath(value)
        if normalized.startswith("../") or normalized in {".", ".."}:
            raise ValueError(f"{label}_escape")
        return normalized

    @classmethod
    def _string_list(
        cls,
        raw: Any,
        label: str,
        *,
        limit: int,
        path_patterns: bool = False,
        concrete_paths: bool = False,
    ) -> list[str]:
        if not isinstance(raw, list):
            raise ValueError(f"{label}_invalid")
        if len(raw) > limit:
            raise ValueError(f"{label}_over_limit")
        values: list[str] = []
        for index, item in enumerate(raw):
            if path_patterns:
                value = cls._path(item, f"{label}_{index}", pattern=True)
            elif concrete_paths:
                value = cls._path(item, f"{label}_{index}", pattern=False)
            else:
                value = cls._text(item, f"{label}_{index}")
            values.append(value)
        return sorted(set(values))

    @classmethod
    def compile_intent(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise ValueError("intent_missing")
        unknown = set(raw) - cls.INTENT_KEYS
        if unknown:
            raise ValueError("intent_keys_unknown:" + ",".join(sorted(unknown)))
        intent = {
            "schema": "glaciereq.pipeline-intent.v1",
            "project_id": cls._text(raw.get("project_id"), "intent_project_id"),
            "allowed_environments": cls._string_list(
                raw.get("allowed_environments"),
                "intent_allowed_environments",
                limit=64,
            ),
            "read_paths": cls._string_list(
                raw.get("read_paths"),
                "intent_read_paths",
                limit=cls.MAX_PATTERNS,
                path_patterns=True,
            ),
            "write_paths": cls._string_list(
                raw.get("write_paths"),
                "intent_write_paths",
                limit=cls.MAX_PATTERNS,
                path_patterns=True,
            ),
            "allowed_secrets": cls._string_list(
                raw.get("allowed_secrets"),
                "intent_allowed_secrets",
                limit=cls.MAX_SECRETS,
            ),
        }
        if not intent["allowed_environments"]:
            raise ValueError("intent_allowed_environments_empty")
        intent["contract_digest"] = _digest(intent)
        return intent

    @classmethod
    def _job(cls, raw: Any, index: int) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise ValueError(f"job_{index}_not_object")
        unknown = set(raw) - cls.JOB_KEYS
        if unknown:
            raise ValueError(f"job_{index}_keys_unknown:" + ",".join(sorted(unknown)))
        return {
            "job_id": cls._text(raw.get("job_id"), f"job_{index}_id"),
            "environment": cls._text(raw.get("environment"), f"job_{index}_environment"),
            "reads": cls._string_list(
                raw.get("reads", []),
                f"job_{index}_reads",
                limit=cls.MAX_ITEMS_PER_JOB,
                concrete_paths=True,
            ),
            "writes": cls._string_list(
                raw.get("writes", []),
                f"job_{index}_writes",
                limit=cls.MAX_ITEMS_PER_JOB,
                concrete_paths=True,
            ),
            "secrets": cls._string_list(
                raw.get("secrets", []),
                f"job_{index}_secrets",
                limit=cls.MAX_ITEMS_PER_JOB,
            ),
        }

    @staticmethod
    def _matches(path: str, patterns: Sequence[str]) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)

    @classmethod
    def verify_plan(
        cls,
        contract: Mapping[str, Any],
        raw_plan: Any,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
        if not isinstance(raw_plan, list):
            raise ValueError("execution_plan_missing")
        if len(raw_plan) > cls.MAX_JOBS:
            raise ValueError("execution_plan_over_limit")
        jobs = [cls._job(raw, index) for index, raw in enumerate(raw_plan)]
        if len({job["job_id"] for job in jobs}) != len(jobs):
            raise ValueError("duplicate_job_id")
        violations: list[dict[str, Any]] = []
        item_count = 0
        allowed_envs = set(contract["allowed_environments"])
        allowed_secrets = set(contract["allowed_secrets"])
        for job in jobs:
            if job["environment"] not in allowed_envs:
                violations.append(
                    {
                        "job_id": job["job_id"],
                        "kind": "environment_drift",
                        "value": job["environment"],
                    }
                )
            for path in job["reads"]:
                item_count += 1
                if not cls._matches(path, contract["read_paths"]):
                    violations.append(
                        {"job_id": job["job_id"], "kind": "read_path_drift", "value": path}
                    )
            for path in job["writes"]:
                item_count += 1
                if not cls._matches(path, contract["write_paths"]):
                    violations.append(
                        {"job_id": job["job_id"], "kind": "write_path_drift", "value": path}
                    )
            for secret in job["secrets"]:
                item_count += 1
                if secret not in allowed_secrets:
                    violations.append(
                        {"job_id": job["job_id"], "kind": "secret_drift", "value": secret}
                    )
        violations.sort(key=lambda value: (value["job_id"], value["kind"], value["value"]))
        return jobs, violations, item_count

    def evaluate(self, req: PipelineIntentContractRequest) -> PipelineIntentContractReceipt:
        if not isinstance(req, PipelineIntentContractRequest):
            raise TypeError("req must be PipelineIntentContractRequest")
        reasons: list[str] = []
        try:
            subject_id = self._text(req.subject_id, "subject_id")
        except ValueError as exc:
            subject_id = ""
            reasons.append(str(exc))
        try:
            budget = self._number(req.budget, "budget", minimum=0.001)
        except ValueError as exc:
            budget = 0.0
            reasons.append(str(exc))
        if not isinstance(req.payload, Mapping):
            payload: Mapping[str, Any] = {}
            reasons.append("payload_not_object")
        else:
            payload = req.payload
            unknown = set(payload) - self.VALID_PAYLOAD_KEYS
            if unknown:
                reasons.append("payload_keys_unknown:" + ",".join(sorted(unknown)))

        now: float | None = None
        if payload.get("now") is not None:
            try:
                now = self._number(payload.get("now"), "now")
            except ValueError as exc:
                reasons.append(str(exc))
        if req.not_after is not None:
            try:
                not_after = self._number(req.not_after, "not_after")
                if now is None:
                    reasons.append("not_after_requires_now")
                elif now > not_after:
                    reasons.append("request_expired")
            except ValueError as exc:
                reasons.append(str(exc))

        result: dict[str, Any] = {}
        work_units = self.BASE_WORK
        try:
            mode = self._text(payload.get("mode", "verify"), "mode").lower()
            if mode not in self.MODES:
                raise ValueError("mode_invalid")
            contract = self.compile_intent(payload.get("intent"))
            expected = payload.get("expected_contract_digest")
            if expected is not None:
                expected = self._text(expected, "expected_contract_digest").lower()
                if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
                    raise ValueError("expected_contract_digest_invalid")
                if expected != contract["contract_digest"]:
                    reasons.append("expected_contract_digest_mismatch")

            if mode == "compile":
                result = {"mode": mode, "contract": contract}
            else:
                jobs, violations, item_count = self.verify_plan(
                    contract, payload.get("execution_plan")
                )
                work_units += (len(jobs) + item_count) * self.ITEM_WORK
                if violations:
                    reasons.append("pipeline_intent_drift")
                result = {
                    "mode": mode,
                    "contract": contract,
                    "execution_plan": jobs,
                    "execution_plan_digest": _digest(jobs),
                    "violations": violations,
                    "verified_job_count": len(jobs),
                }
            if work_units > budget:
                reasons.append("work_budget_exceeded")
        except ValueError as exc:
            reasons.append(str(exc))

        decision = Decision.REFUSE if reasons else Decision.ALLOW
        if not reasons:
            reasons = [
                "pipeline_intent_compiled" if result.get("mode") == "compile" else "pipeline_plan_matches_frozen_intent"
            ]
        metrics = {
            "work_units": work_units,
            "budget_units": budget,
            "violation_count": len(result.get("violations", [])),
            "job_count": len(result.get("execution_plan", [])),
        }
        digest = _digest(
            {
                "subject_id": subject_id,
                "decision": decision.value,
                "reasons": reasons,
                "result": result,
                "metrics": metrics,
            }
        )
        return PipelineIntentContractReceipt(
            decision=decision,
            reasons=tuple(reasons),
            digest=digest,
            metrics=metrics,
            result=result,
        )


Mechanism = PipelineIntentContract


def _read_input(path: str | None) -> str:
    limit = PipelineIntentContract.MAX_INPUT_CHARS
    if path:
        source = Path(path)
        if source.stat().st_size > limit * 4:
            raise ValueError("input_too_large")
        raw = source.read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input_too_large")
    return raw


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile a pipeline intent or verify an execution plan against frozen intent."
    )
    parser.add_argument("--input", "-i", help="request JSON file; defaults to stdin")
    args = parser.parse_args(argv)
    try:
        data = json.loads(_read_input(args.input))
        if not isinstance(data, Mapping):
            raise ValueError("request JSON must be an object")
        payload = data.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be an object")
        receipt = PipelineIntentContract().evaluate(
            PipelineIntentContractRequest(
                subject_id=data.get("subject_id", ""),
                payload=dict(payload),
                budget=data.get("budget", 4.0),
                grant_id=data.get("grant_id"),
                not_after=data.get("not_after"),
            )
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "decision": "REFUSE",
                    "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"],
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2
