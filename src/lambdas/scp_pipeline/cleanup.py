# src/lambdas/scp_pipeline/cleanup.py
import os, json
from typing import Any, Dict
from .common.aws import s3_delete

ARTIFACT_BUCKET = os.environ.get("ARTIFACT_BUCKET","")
ARTIFACT_PREFIX = os.environ.get("ARTIFACT_PREFIX","generated/scp")

def _ok(payload: Dict[str, Any]): return {"statusCode": 200, "body": json.dumps(payload)}
def _err(msg: str, code=500): return {"statusCode": code, "body": json.dumps({"error": msg})}

def lambda_handler(event, _ctx):
    """
    Minimal cleanup: remove standard bundle + metadata for this pipeline.
    If you want policyId-specific paths, extend to derive per-policy keys.
    """
    try:
        keys = [f"{ARTIFACT_PREFIX}/bundle.tar.gz", f"{ARTIFACT_PREFIX}/metadata.json"]
        for k in keys:
            s3_delete(ARTIFACT_BUCKET, k)
        return _ok({"deleted": keys})
    except Exception as e:
        return _err(f"cleanup failed: {e}")
