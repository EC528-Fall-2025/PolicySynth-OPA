# src/lambdas/scp_sync/aws.py
import os
import json
import boto3
from typing import List, Dict, Any

def _region() -> str:
    # Keep tests and local runs happy without config
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

def _s3():
    # Allow LocalStack via env var in local tests
    endpoint = os.environ.get("AWS_ENDPOINT_URL_S3")
    kwargs = {"region_name": _region()}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client("s3", **kwargs)

def _orgs():
    return boto3.client("organizations", region_name=_region())

def list_scps() -> List[Dict[str, Any]]:
    # Pull all Service Control Policies in the org
    orgs = _orgs()
    paginator = orgs.get_paginator("list_policies")
    pages = paginator.paginate(Filter="SERVICE_CONTROL_POLICY")
    scps = []
    for page in pages:
        for pol in page.get("Policies", []):
            detail = orgs.describe_policy(PolicyId=pol["Id"])["Policy"]
            content = detail.get("Content", "{}")
            scps.append({"id": pol["Id"], "name": pol["Name"], "content": json.loads(content)})
    return scps

def put_object(bucket: str, key: str, body: bytes, content_type: str = "application/octet-stream"):
    _s3().put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)

def get_object(bucket: str, key: str) -> bytes:
    resp = _s3().get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()

def delete_object(bucket: str, key: str):
    _s3().delete_object(Bucket=bucket, Key=key)
