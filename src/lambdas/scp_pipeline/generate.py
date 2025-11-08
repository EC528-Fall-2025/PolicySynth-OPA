# Turns retrieved SCP into an OPA bundle (.tar.gz) and returns base64 bundle + metadata
from typing import Any, Dict
import json, io, tarfile, time
from .common import ok, err, b64e
from src.lambdas.scp_sync.policy_generator import scps_to_rego_bundle

def lambda_handler(event, _ctx):
    try:
        scp = (event or {}).get("scp")
        if not scp:
            return err("missing 'scp' in input", 400)
        bundle_bytes, meta = scps_to_rego_bundle([scp])
        return ok({"scp": scp, "bundle_b64": b64e(bundle_bytes), "meta": meta})
    except Exception as e:
        return err(f"generate failed: {e}")
