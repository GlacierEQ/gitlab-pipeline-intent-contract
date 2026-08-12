from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline_intent_contract import Decision, PipelineIntentContract, PipelineIntentContractRequest


def demo_payload() -> dict:
    return {"intent_contract":{"objective":"build and deploy without authority expansion","forbidden_paths":["secrets/**"],"forbidden_secrets":["ROOT_TOKEN"],"protected_environments":["production"],"jobs":[{"job_id":"test","path_patterns":["src/**","tests/**"],"secrets":[],"environments":[],"permissions":["repo.read"],"required_dependencies":[]},{"job_id":"deploy","path_patterns":["dist/**"],"secrets":["DEPLOY_TOKEN"],"environments":["production"],"permissions":["repo.read","deploy.write"],"required_dependencies":["test"]}]},"actual_jobs":[{"job_id":"test","paths":["src/app.py","tests/test_app.py"],"secrets":[],"environment":None,"permissions":["repo.read"],"completed_dependencies":[]},{"job_id":"deploy","paths":["dist/app.whl"],"secrets":["DEPLOY_TOKEN"],"environment":"production","permissions":["repo.read","deploy.write"],"completed_dependencies":["test"]}],"protected_environment_approvals":["production"]}


def main() -> int:
    parser=argparse.ArgumentParser(description="Verify a CI pipeline against frozen path, secret, environment, and permission intent")
    parser.add_argument("--input",type=Path)
    parser.add_argument("--subject",default="pipeline-demo")
    args=parser.parse_args()
    payload=json.loads(args.input.read_text()) if args.input else demo_payload()
    receipt=PipelineIntentContract().evaluate(PipelineIntentContractRequest(args.subject,payload,1.0))
    print(json.dumps(receipt.as_dict(),indent=2,sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2

if __name__=="__main__":
    raise SystemExit(main())
