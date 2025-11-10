# src/lambdas/scp_pipeline/validate.py
import json, os
from typing import Any, Dict
from .common.aws import s3_get
from .common.opa_validator import validate_bundle

BUCKET = os.environ["ARTIFACT_BUCKET"]

def lambda_handler(event: Dict[str, Any], _ctx):
    g = event.get("generated") or event
    key = g.get("bundle_key")
    if not key:
        return {"ok": False, "error": "no bundle_key"}
    bundle = s3_get(BUCKET, key)
    report = validate_bundle(bundle)
    return {"ok": report.get("ok", False), "report": report, "bundle_key": key}
