# Retrieves SCP JSON. Accepts:
# - EventBridge Organizations event (CreatePolicy/UpdatePolicy/DeletePolicy) with detail.requestParameters.content
# - {"scp": {...json...}} inline
# - {"policy_id": "p-123"} to fetch via Organizations
import json
from typing import Any, Dict
from .aws_clients import orgs
from .common import ok, err

def _from_eventbridge(event: Dict[str, Any]):
    d = event.get("detail", {})
    # Create/Update have requestParameters.content; Delete has requestParameters.policyId
    content = d.get("requestParameters", {}).get("content")
    policy_id = d.get("responseElements", {}).get("policy", {}).get("policySummary", {}).get("id") \
                or d.get("requestParameters", {}).get("policyId")
    name = d.get("responseElements", {}).get("policy", {}).get("policySummary", {}).get("name")
    if content:
        try:
            scp_json = json.loads(content)
        except Exception:
            # Some CloudTrail payloads already JSON; try passthrough
            scp_json = content
        return {"id": policy_id or "unknown", "name": name or "unknown", "content": scp_json}
    if policy_id:
        return _describe(policy_id)
    return None

def _describe(policy_id: str):
    o = orgs()
    pol = o.describe_policy(PolicyId=policy_id)["Policy"]
    content = json.loads(pol.get("Content", "{}"))
    return {"id": pol["PolicySummary"]["Id"], "name": pol["PolicySummary"]["Name"], "content": content}

def lambda_handler(event, _ctx):
    try:
        if "detail" in (event or {}):
            scp = _from_eventbridge(event)
            if scp: return ok({"scp": scp})
        if "scp" in (event or {}):
            return ok({"scp": event["scp"]})
        if "policy_id" in (event or {}):
            return ok({"scp": _describe(event["policy_id"])})
        return err("No SCP found in event (need EventBridge detail, 'scp', or 'policy_id')", 400)
    except Exception as e:
        return err(f"retrieve failed: {e}")
