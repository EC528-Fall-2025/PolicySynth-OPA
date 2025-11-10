import json, os
from typing import Any, Dict, List
from .aws_clients import orgs, s3
from ..scp_sync.policy_generator import scps_to_bundle
from .opa_validator import run_validation
from .deployer import deploy_bundle

ARTIFACT_BUCKET  = os.environ.get("ARTIFACT_BUCKET", "")
ARTIFACT_PREFIX  = os.environ.get("ARTIFACT_PREFIX", "generated/scp")
RAW_SCP_PREFIX   = os.environ.get("RAW_SCP_PREFIX", "raw/scp")  # if events are stored to S3
WRITE_INTERMEDIATE = os.environ.get("WRITE_INTERMEDIATE", "true").lower() == "true"

def _ok(body: Dict[str, Any], status=200): return {"statusCode": status, "body": json.dumps(body)}
def _err(msg: str, status=500):            return {"statusCode": status, "body": json.dumps({"error": msg})}

def _list_all_scps() -> List[Dict[str, Any]]:
    o = orgs()
    paginator = o.get_paginator("list_policies")
    scps = []
    for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
        for pol in page.get("Policies", []):
            pol_full = o.describe_policy(PolicyId=pol["Id"])["Policy"]
            content = pol_full.get("Content", "{}")
            scps.append({"id": pol["Id"], "name": pol["Name"], "content": json.loads(content)})
    return scps

def _load_scps_from_event_or_s3(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Step Function passes {"source":"aws.organizations", "detail-type":"AWS API Call via CloudTrail",
      "detail":{"eventName":"CreatePolicy"|"UpdatePolicy"|"DeletePolicy", ...}} or a custom wrapper
    Optionally, an S3 location with the SCP JSON is provided:
      {"scp_s3":{"bucket":"...", "key":"..."}}
    If neither is provided, we fetch all SCPs via Orgs (useful for nightly sync).
    """
    if isinstance(event, dict) and event.get("scp_s3"):
        b = event["scp_s3"]["bucket"]; k = event["scp_s3"]["key"]
        obj = s3().get_object(Bucket=b, Key=k)["Body"].read()
        content = json.loads(obj.decode())
        # support single or list in the payload
        if isinstance(content, dict): content = [content]
        return [{"id": p.get("Id", "unknown"), "name": p.get("Name","scp"), "content": p.get("Content", {})} for p in content]

    # If called from EventBridge/CloudTrail with policy Id in detail
    detail = (event or {}).get("detail", {})
    pol_id = None
    # Some orgs events include "requestParameters":{"policyId":"p-abc..."}
    rp = detail.get("requestParameters") or {}
    pol_id = rp.get("policyId") or rp.get("policyIdList", [None])[0]
    if pol_id:
        o = orgs()
        d = o.describe_policy(PolicyId=pol_id)["Policy"]
        return [{"id": pol_id, "name": d["PolicySummary"]["Name"], "content": json.loads(d["Content"])}]

    # Fallback: full scan
    return _list_all_scps()

def _write_intermediates(bundle: bytes, meta: Dict[str, Any]):
    if not WRITE_INTERMEDIATE or not ARTIFACT_BUCKET: return
    s3().put_object(Bucket=ARTIFACT_BUCKET, Key=f"{ARTIFACT_PREFIX}/bundle.tar.gz", Body=bundle, ContentType="application/gzip")
    s3().put_object(Bucket=ARTIFACT_BUCKET, Key=f"{ARTIFACT_PREFIX}/metadata.json", Body=json.dumps(meta).encode(), ContentType="application/json")

def lambda_handler(event, _context):
    """
    Single entrypoint used by the Step Function. The Step Function will pass
    {"stage":"retrieve_generate_validate_deploy", ...event passthrough...}
    Stages supported (in case you want to call pieces directly):
      - retrieve_generate
      - validate
      - deploy
      - retrieve_generate_validate_deploy (default)
    """
    try:
        stage = (event or {}).get("stage", "retrieve_generate_validate_deploy")

        if stage == "retrieve_generate":
            scps = _load_scps_from_event_or_s3(event or {})
            bundle, meta = scps_to_bundle(scps)
            _write_intermediates(bundle, meta)
            return _ok({"bundle_b64": bundle.hex(), "meta": meta}, 200)

        if stage == "validate":
            # expects event to carry prior hex bundle
            bundle_hex = event.get("bundle_b64")
            if bundle_hex is None:
                return _err("validate requires 'bundle_b64' in event", 400)
            bundle = bytes.fromhex(bundle_hex)
            report = run_validation(bundle)
            return _ok({"validation": report}, 200)

        if stage == "deploy":
            bundle_hex = event.get("bundle_b64")
            meta = event.get("meta", {})
            if bundle_hex is None:
                return _err("deploy requires 'bundle_b64' in event", 400)
            bundle = bytes.fromhex(bundle_hex)
            out = deploy_bundle(bundle, meta)
            return _ok({"deployed": out}, 200)

        # default full flow
        scps = _load_scps_from_event_or_s3(event or {})
        bundle, meta = scps_to_bundle(scps)
        _write_intermediates(bundle, meta)
        validation = run_validation(bundle)
        deployed = deploy_bundle(bundle, meta)
        return _ok({"meta": meta, "validation": validation, "deployed": deployed}, 200)

    except Exception as e:
        return _err(f"{type(e).__name__}: {e}")
