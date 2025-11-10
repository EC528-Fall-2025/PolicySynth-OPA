import json, os
from typing import Any, Dict, Tuple
from .aws_clients import s3

ARTIFACT_BUCKET = os.environ.get("ARTIFACT_BUCKET", "")
DIST_PREFIX     = os.environ.get("DIST_PREFIX",  "dist/scp")

def deploy_bundle(bundle: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ship the generated bundle to the "distribution" prefix where your
    IaC pipelines can pick it up (e.g., curl from S3 or sync in CI).
    """
    if not ARTIFACT_BUCKET:
        raise RuntimeError("ARTIFACT_BUCKET env var not set")

    bundle_key = f"{DIST_PREFIX}/bundle.tar.gz"
    meta_key   = f"{DIST_PREFIX}/metadata.json"
    s3().put_object(Bucket=ARTIFACT_BUCKET, Key=bundle_key, Body=bundle, ContentType="application/gzip")
    s3().put_object(Bucket=ARTIFACT_BUCKET, Key=meta_key, Body=json.dumps(metadata).encode(), ContentType="application/json")
    return {"bucket": ARTIFACT_BUCKET, "bundle_key": bundle_key, "metadata_key": meta_key}
