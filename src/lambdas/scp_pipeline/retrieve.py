# src/lambdas/scp_pipeline/retrieve.py
import json, os
from typing import Any, Dict
from .common.aws import list_scps_from_orgs, s3_put

BUCKET = os.environ["ARTIFACT_BUCKET"]
PREFIX = os.environ.get("ARTIFACT_PREFIX","generated/scp")

def lambda_handler(event: Dict[str, Any], _ctx):
    """
    Input example (from EventBridge InputTransformer):
    {
      "action": "CreatePolicy|UpdatePolicy|DeletePolicy",
      "policyId": "...",
      "policyName": "...",
      "policyContent": {...}  # may be missing on delete
    }
    """
    action = event.get("action")
    if action == "DeletePolicy":
        # nothing to retrieve; pass through
        return {"action": action, "retrieved_key": None}

    # Prefer event payload if present; else fetch all SCPs as source of truth
    if "policyContent" in event and event["policyContent"]:
      scps = [{"id": event.get("policyId"), "name": event.get("policyName","scp"),
               "content": json.loads(event["policyContent"]) if isinstance(event["policyContent"], str)
                          else event["policyContent"]}]
    else:
      scps = list_scps_from_orgs()

    key = f"{PREFIX}/raw_scps.json"
    s3_put(BUCKET, key, json.dumps(scps).encode("utf-8"), "application/json")
    return {"action": action, "retrieved_key": key}
