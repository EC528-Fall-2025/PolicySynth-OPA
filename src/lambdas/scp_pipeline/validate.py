# Validates the base64 bundle with OPA binary from layer; returns report and passes bundle through
from typing import Any, Dict
from .common import ok, err, b64d
from src.lambdas.scp_pipeline.opa_validator import run_validation_suite

def lambda_handler(event, _ctx):
    try:
        bundle_b64 = (event or {}).get("bundle_b64")
        if not bundle_b64:
            return err("missing 'bundle_b64' in input", 400)
        bundle = b64d(bundle_b64)
        report = run_validation_suite(bundle)
        return ok({"scp": event.get("scp"), "bundle_b64": bundle_b64, "meta": event.get("meta"), "report": report})
    except Exception as e:
        return err(f"validate failed: {e}")
