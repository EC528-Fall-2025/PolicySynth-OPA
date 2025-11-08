import os, boto3

def _region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

def s3():
    kwargs = {"region_name": _region()}
    ep = os.environ.get("AWS_ENDPOINT_URL_S3")
    if ep: kwargs["endpoint_url"] = ep
    return boto3.client("s3", **kwargs)

def orgs():
    return boto3.client("organizations", region_name=_region())
