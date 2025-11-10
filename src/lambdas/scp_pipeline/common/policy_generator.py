# src/lambdas/scp_pipeline/common/policy_generator.py
import io, json, tarfile, time
from typing import List, Dict, Any

def _rego_from_scp(scp: Dict[str, Any]) -> str:
    statements = scp["content"].get("Statement", [])
    pkg = f"""package scp.v1

# Auto-generated from {scp["name"]}
deny[reason] {{
  input.action = action
  some i
  stmt := statements[i]
  stmt.Effect == "Deny"
  action_matches(stmt.Actions, action)
  reason := stmt
}}

action_matches(patterns, action) {{
  some p
  p := patterns[_]
  glob.match(p, [], action)
}}

statements := {json.dumps(statements)}
"""
    return pkg

def make_bundle(scps: List[Dict[str, Any]]):
    meta = {"source":"AWS Organizations SCP","count":len(scps),"generated_at":int(time.time())}
    buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buf) as tar:
        _add_bytes(tar, json.dumps(meta, indent=2).encode(), "data/metadata.json")
        for scp in scps:
            rego = _rego_from_scp(scp).encode()
            name = scp["name"].replace(" ","_").replace("/","_").lower()
            _add_bytes(tar, rego, f"policy/{name}.rego")
    return buf.getvalue(), meta

def _add_bytes(tar: tarfile.TarFile, content: bytes, path: str):
    info = tarfile.TarInfo(path); info.size = len(content)
    tar.addfile(info, io.BytesIO(content))
