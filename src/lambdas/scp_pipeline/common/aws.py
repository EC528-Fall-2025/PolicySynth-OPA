# src/lambdas/scp_pipeline/common/aws.py
import os, json, boto3
from typing import Any, Dict, List

def _region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

def s3_client():
    kwargs = {"region_name": _region()}
    ep = os.environ.get("AWS_ENDPOINT_URL_S3")
    if ep:
        kwargs["endpoint_url"] = ep
    return boto3.client("s3", **kwargs)

def orgs_client():
    return boto3.client("organizations", region_name=_region())

def s3_put(bucket: str, key: str, body: bytes, content_type: str = "application/octet-stream"):
    s3_client().put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)

def s3_get(bucket: str, key: str) -> bytes:
    return s3_client().get_object(Bucket=bucket, Key=key)["Body"].read()

def s3_delete(bucket: str, key: str):
    s3_client().delete_object(Bucket=bucket, Key=key)

def list_scps_from_orgs() -> List[Dict[str, Any]]:
    orgs = orgs_client()
    paginator = orgs.get_paginator("list_policies")
    pages = paginator.paginate(Filter="SERVICE_CONTROL_POLICY")
    out: List[Dict[str, Any]] = []
    for page in pages:
        for pol in page.get("Policies", []):
            detail = orgs.describe_policy(PolicyId=pol["Id"])["Policy"]
            content = detail.get("Content", "{}")
            out.append({"id": pol["Id"], "name": pol["Name"], "content": json.loads(content)})
    return out
