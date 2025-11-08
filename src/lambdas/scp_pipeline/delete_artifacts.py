# Deletes artifacts for a given policy id (or prefix) in S3.
from typing import Any, Dict
from .aws_clients import s3
from .common import ok, err, env

def lambda_handler(event, _ctx):
    try:
        bucket = env("ARTIFACT_BUCKET")
        prefix = env("ARTIFACT_PREFIX", "generated/scp")
        if not bucket: return err("ARTIFACT_BUCKET env required", 500)

        # policy id from EventBridge delete or direct input
        pol_id = None
        if "detail" in (event or {}):
            pol_id = event["detail"].get("requestParameters", {}).get("policyId")
        pol_id = pol_id or event.get("policy_id") or (event.get("scp", {}) or {}).get("id")
        if not pol_id: return err("missing policy id to delete", 400)

        base_prefix = f"{prefix}/{pol_id}/"
        # List and delete under the prefix
        c = s3()
        keys = []
        cont = None
        while True:
            resp = c.list_objects_v2(Bucket=bucket, Prefix=base_prefix, ContinuationToken=cont) if cont else \
                   c.list_objects_v2(Bucket=bucket, Prefix=base_prefix)
            for obj in resp.get("Contents", []) or []:
                keys.append({"Key": obj["Key"]})
            if resp.get("IsTruncated"):
                cont = resp.get("NextContinuationToken")
            else:
                break
        if keys:
            c.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
        return ok({"deleted_prefix": base_prefix, "deleted_count": len(keys)})
    except Exception as e:
        return err(f"delete failed: {e}")
