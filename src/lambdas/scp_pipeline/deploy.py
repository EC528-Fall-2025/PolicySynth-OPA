# src/lambdas/scp_pipeline/deploy.py
import os
from typing import Any, Dict
from .common.aws import s3_get, s3_put

BUCKET = os.environ["ARTIFACT_BUCKET"]
PUBLISHED_PREFIX = os.environ.get("PUBLISHED_PREFIX","published/scp")

def lambda_handler(event: Dict[str, Any], _ctx):
    g = event.get("generated") or {}
    v = event.get("validated") or {}
    if not v.get("ok"):
        # fail closed; Step Functions will surface failure
        raise RuntimeError(f"validation failed: {v}")

    key = g.get("bundle_key")
    if not key:
        raise RuntimeError("missing bundle_key")

    final_key = f"{PUBLISHED_PREFIX}/bundle.tar.gz"
    s3_put(BUCKET, final_key, s3_get(BUCKET, key), "application/gzip")
    return {"published_key": final_key}
