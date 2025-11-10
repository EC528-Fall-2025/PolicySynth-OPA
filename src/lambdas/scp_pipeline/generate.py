# src/lambdas/scp_pipeline/generate.py
import json, os
from typing import Any, Dict, List
from .common.aws import s3_get, s3_put
from .common.policy_generator import make_bundle

BUCKET = os.environ["ARTIFACT_BUCKET"]
PREFIX = os.environ.get("ARTIFACT_PREFIX","generated/scp")

def lambda_handler(event: Dict[str, Any], _ctx):
    r = event.get("retrieved") or event  # supports direct invoke or SF input
    raw_key = r.get("retrieved_key")
    if not raw_key:
        return {"error": "no retrieved_key", "input": event}

    scps: List[Dict[str, Any]] = json.loads(s3_get(BUCKET, raw_key))
    bundle_bytes, meta = make_bundle(scps)
    bundle_key = f"{PREFIX}/bundle.tar.gz"
    meta_key = f"{PREFIX}/metadata.json"

    s3_put(BUCKET, bundle_key, bundle_bytes, "application/gzip")
    s3_put(BUCKET, meta_key, json.dumps(meta).encode(), "application/json")
    return {"bundle_key": bundle_key, "meta_key": meta_key}
