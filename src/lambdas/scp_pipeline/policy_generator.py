import io, json, tarfile, time
from typing import Any, Dict, List, Tuple

def _rego_from_scp(name: str, content: Dict[str, Any]) -> str:
    statements = content.get("Statement", [])
    pkg = f"""package scp.v1

# Auto-generated from SCP: {name}
import future.keywords.every
import future.keywords.in

deny[stmt] {{
  some i
  stmt := statements[i]
  stmt.Effect == "Deny"
  action := input.action
  action_matches(stmt.Actions, action)
}}

action_matches(patterns, action) {{
  some p
  p := patterns[_]
  glob.match(p, [], action)
}}

# embedded SCP statements
statements := {json.dumps(statements)}
"""
    return pkg

def scps_to_bundle(scps: List[Dict[str, Any]]) -> Tuple[bytes, Dict[str, Any]]:
    """
    Returns (bundle_bytes, metadata). Bundle layout:
      data/metadata.json
      policy/<name>.rego
    """
    meta = {
        "source": "aws-organizations-scp",
        "count": len(scps),
        "generated_at": int(time.time()),
    }
    buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buf) as tar:
        _add_bytes(tar, json.dumps(meta, indent=2).encode(), "data/metadata.json")
        for scp in scps:
            safe = scp["name"].replace(" ", "_").replace("/", "_").lower()
            rego = _rego_from_scp(scp["name"], scp["content"]).encode()
            _add_bytes(tar, rego, f"policy/{safe}.rego")
    return buf.getvalue(), meta

def _add_bytes(tar: tarfile.TarFile, content: bytes, arcname: str):
    info = tarfile.TarInfo(arcname)
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))
