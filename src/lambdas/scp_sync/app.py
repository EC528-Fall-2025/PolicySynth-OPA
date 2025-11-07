import json
import os

# 🔄 import modules (so tests can monkeypatch attributes)
from . import aws
from . import policy_generator
from . import opa_validator

def _env():
    bucket = os.environ.get("ARTIFACT_BUCKET", "")
    prefix = os.environ.get("ARTIFACT_PREFIX", "generated/scp")
    return bucket, prefix

def _ok(body, status=200):
    return {"statusCode": status, "body": json.dumps(body)}

def _err(msg, status=500):
    return {"statusCode": status, "body": json.dumps({"error": msg})}

def handle_create(event, _ctx):
    try:
        bucket, prefix = _env()
        if not bucket:
            return _err("ARTIFACT_BUCKET env var is required", status=500)

        scps = aws.list_scps()
        bundle_bytes, meta = policy_generator.scps_to_rego_bundle(scps)
        report = opa_validator.run_validation_suite(bundle_bytes)

        bundle_key = f"{prefix}/bundle.tar.gz"
        meta_key = f"{prefix}/metadata.json"
        aws.put_object(bucket, bundle_key, bundle_bytes, content_type="application/gzip")
        aws.put_object(bucket, meta_key, json.dumps(meta).encode("utf-8"))

        return _ok({"message": "created", "bundle_key": bundle_key, "report": report})
    except Exception as e:
        return _err(f"create failed: {e}")

def handle_update(event, _ctx):
    try:
        bucket, prefix = _env()
        if not bucket:
            return _err("ARTIFACT_BUCKET env var is required", status=500)

        scps = aws.list_scps()
        bundle_bytes, meta = policy_generator.scps_to_rego_bundle(scps)
        report = opa_validator.run_validation_suite(bundle_bytes)

        bundle_key = f"{prefix}/bundle.tar.gz"
        meta_key = f"{prefix}/metadata.json"
        aws.put_object(bucket, bundle_key, bundle_bytes, content_type="application/gzip")
        aws.put_object(bucket, meta_key, json.dumps(meta).encode("utf-8"))

        return _ok({"message": "updated", "bundle_key": bundle_key, "report": report})
    except Exception as e:
        return _err(f"update failed: {e}")

def handle_delete(event, _ctx):
    try:
        bucket, prefix = _env()
        if not bucket:
            return _err("ARTIFACT_BUCKET env var is required", status=500)

        bundle_key = f"{prefix}/bundle.tar.gz"
        meta_key   = f"{prefix}/metadata.json"
        aws.delete_object(bucket, bundle_key)
        aws.delete_object(bucket, meta_key)
        return _ok({"message": "deleted", "deleted_keys": [bundle_key, meta_key]})
    except Exception as e:
        return _err(f"delete failed: {e}")

def lambda_handler(event, context):
    action = (event or {}).get("action") or (event.get("detail", {}).get("action") if isinstance(event, dict) else None)
    if action == "create": return handle_create(event, context)
    if action == "update": return handle_update(event, context)
    if action == "delete": return handle_delete(event, context)
    return _err("action must be one of: create, update, delete", status=400)
