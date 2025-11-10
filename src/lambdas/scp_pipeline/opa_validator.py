import json, os, shutil, subprocess, tempfile, tarfile
from typing import Any, Dict

OPA_BIN = os.environ.get("OPA_BIN", "/opt/bin/opa")

def run_validation(bundle_bytes: bytes) -> Dict[str, Any]:
    """
    If OPA is available (via Lambda layer), runs a basic eval:
      data.scp.v1.deny with input {action:"iam:PassRole"}
    Otherwise, returns a soft "skipped" result so your pipeline continues.
    """
    if not shutil.which(OPA_BIN) and not os.path.exists(OPA_BIN):
        return {"status": "skipped", "reason": f"opa not found at {OPA_BIN}"}

    with tempfile.TemporaryDirectory() as td:
        bpath = os.path.join(td, "bundle.tar.gz")
        with open(bpath, "wb") as f:
            f.write(bundle_bytes)

        out_dir = os.path.join(td, "bundle")
        os.makedirs(out_dir, exist_ok=True)
        with tarfile.open(bpath, "r:gz") as tar:
            tar.extractall(out_dir)

        cmd = [OPA_BIN, "eval", "-I", "-f", "json", "-d", out_dir, "data.scp.v1.deny", "--input", "-"]
        input_doc = json.dumps({"action": "iam:PassRole"}).encode()
        proc = subprocess.run(cmd, input=input_doc, capture_output=True)
        if proc.returncode != 0:
            return {"status": "error", "stderr": proc.stderr.decode("utf-8")}
        try:
            parsed = json.loads(proc.stdout.decode("utf-8"))
        except Exception:
            parsed = {"raw": proc.stdout.decode("utf-8")}
        return {"status": "ok", "result": parsed}
