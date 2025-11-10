# src/lambdas/scp_pipeline/common/opa_validator.py
import os, json, tempfile, tarfile, subprocess
from typing import Any, Dict

OPA_BIN = os.environ.get("OPA_BIN", "/opt/bin/opa")

def validate_bundle(bundle_bytes: bytes) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        bpath = os.path.join(td, "bundle.tgz")
        with open(bpath, "wb") as f: f.write(bundle_bytes)
        extract = os.path.join(td, "b"); os.makedirs(extract, exist_ok=True)
        with tarfile.open(bpath, "r:gz") as tar: tar.extractall(extract)

        # very basic evaluation for smoke
        return _eval("data.scp.v1.deny", {"action":"iam:PassRole"}, extract)

def _eval(query: str, input_obj: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    proc = subprocess.run(
        [OPA_BIN, "eval", "-I", "-f", "json", "-d", workdir, query, "--input", "-"],
        input=json.dumps(input_obj).encode(),
        capture_output=True
    )
    if proc.returncode != 0:
        return {"ok": False, "stderr": proc.stderr.decode()}
    try:
        return {"ok": True, "result": json.loads(proc.stdout.decode())}
    except Exception:
        return {"ok": True, "raw": proc.stdout.decode()}
