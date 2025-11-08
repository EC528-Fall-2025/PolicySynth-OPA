# Writes bundle + metadata to S3. Keys include policy id + timestamp.
import json, time
from typing import Any, Dict
from .aws_clients import s3
from .common import ok, err, b64d, env, now_ts

def lambda_handler(event, _ctx):
    try:
        scp = event.get("scp") or {}
        bundle_b64 = event.get("bundle_b64")
        meta = event.get("meta") or {}
        if not bundle_b64: return err("missing 'bundle_b64'", 400)

        bucket = env("ARTIFACT_BUCKET")
        prefix = env("ARTIFACT_PREFIX", "generated/scp")
        if not bucket: return err("ARTIFACT_BUCKET env required", 500)

        policy_id = scp.get("id", "unknown")
        ts = str(now_ts())
        base = f"{prefix}/{policy_id}/{ts}"
        bundle_key = f"{base}/bundle.tar.gz"
        meta_key = f"{base}/metadata.json"

        s3().put_object(Bucket=bucket, Key=bundle_key, Body=b64d(bundle_b64), ContentType="application/gzip")
        s3().put_object(Bucket=bucket, Key=meta_key, Body=json.dumps(meta).encode("utf-8"), ContentType="application/json")

        return ok({"scp": scp, "bundle_key": bundle_key, "metadata_key": meta_key})
    except Exception as e:
        return err(f"publish failed: {e}")
