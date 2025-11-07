import json
import os
import subprocess
import tempfile
import tarfile
from typing import Dict, Any

# This assumes Lambda has OPA binary in /opt/bin/opa via a layer (see infra below).
OPA_BIN = os.environ.get("OPA_BIN", "/opt/bin/opa")

# Optional: a repo test suite baked into the bundle under /tests/scp/
# The validator runs a very simple sanity evaluation by default.
def run_validation_suite(bundle_bytes: bytes) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        bundle_path = os.path.join(td, "bundle.tar.gz")
        with open(bundle_path, "wb") as f:
            f.write(bundle_bytes)
        # Extract to a folder OPA can read
        extract_dir = os.path.join(td, "bundle")
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(bundle_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        # Basic check: evaluate deny with a dummy input; ensure no hard failure
        input_doc = {"action": "iam:PassRole"}
        result = _opa_eval(package="data.scp.v1.deny", input_obj=input_doc, workdir=extract_dir)
        return {"eval_result": result}

def _opa_eval(package: str, input_obj: Dict[str, Any], workdir: str) -> Any:
    cmd = [OPA_BIN, "eval", "-I", "-f", "json", "-d", workdir, package, "--input", "-"]
    proc = subprocess.run(cmd, input=json.dumps(input_obj).encode("utf-8"), cwd=workdir, capture_output=True, check=False)
    if proc.returncode != 0:
        return {"error": proc.stderr.decode("utf-8")}
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        return {"raw": proc.stdout.decode("utf-8")}
