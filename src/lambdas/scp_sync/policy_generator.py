import io
import json
import tarfile
import time
from typing import List, Dict, Any

# Minimal example Rego generator translating allow/deny SCP statements
# into a package with decision points. Customize to your repo’s conventions.

def _rego_from_scp(scp: Dict[str, Any]) -> str:
    """
    Very simple mapping:
      - SCP 'Deny' statements become rules that deny on matching action/resource/condition.
      - We emit a decision document: data.scp.deny[reason]
    """
    pkg = f'package scp.v1\n\n' \
          f'# Auto-generated from SCP: {scp["name"]}\n' \
          f'deny[reason] {{\n' \
          f'  input.action = action\n' \
          f'  some i\n' \
          f'  deny_stmt := statements[i]\n' \
          f'  deny_stmt.Effect == "Deny"\n' \
          f'  action_matches(deny_stmt.Actions, action)\n' \
          f'  reason := deny_stmt\n' \
          f'}}\n\n' \
          f'# naive match helper\n' \
          f'action_matches(patterns, action) {{\n' \
          f'  some p\n' \
          f'  p := patterns[_]\n' \
          f'  glob.match(p, [], action)\n' \
          f'}}\n'
    # embed SCP statements as data for simplicity
    statements = scp["content"].get("Statement", [])
    data_block = f'# embedded statements\n' \
                 f'statements := {json.dumps(statements)}\n'
    return pkg + "\n" + data_block

def scps_to_rego_bundle(scps: List[Dict[str, Any]]):
    """
    Build an OPA bundle tar.gz:
      /policy/*.rego
      /data/metadata.json
    """
    buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buf) as tar:
        meta = {"source": "AWS Organizations SCP", "count": len(scps), "generated_at": int(time.time())}
        # metadata.json
        meta_bytes = json.dumps(meta, indent=2).encode("utf-8")
        _add_bytes(tar, meta_bytes, "data/metadata.json")
        # rego files
        for scp in scps:
            rego = _rego_from_scp(scp).encode("utf-8")
            safe_name = scp["name"].replace(" ", "_").replace("/", "_").lower()
            _add_bytes(tar, rego, f"policy/{safe_name}.rego")
    return buf.getvalue(), meta

def _add_bytes(tar: tarfile.TarFile, content: bytes, arcname: str):
    ti = tarfile.TarInfo(name=arcname)
    ti.size = len(content)
    tar.addfile(ti, io.BytesIO(content))
