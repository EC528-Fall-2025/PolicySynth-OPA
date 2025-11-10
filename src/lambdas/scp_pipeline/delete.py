# src/lambdas/scp_pipeline/delete.py
import os
from typing import Any, Dict
from .common.aws import s3_client

BUCKET = os.environ["ARTIFACT_BUCKET"]
PREFIX = os.environ.get("ARTIFACT_PREFIX","generated/scp")
PUB = os.environ.get("PUBLISHED_PREFIX","published/scp")

def _del_prefix(prefix: str):
    s3 = s3_client()
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=prefix)
    for obj in (resp.get("Contents") or []):
        s3.delete_object(Bucket=BUCKET, Key=obj["Key"])

def lambda_handler(event: Dict[str, Any], _ctx):
    # Clear staging + published artifacts for simplicity
    _del_prefix(PREFIX)
    _del_prefix(PUB)
    return {"deleted": [PREFIX, PUB]}
