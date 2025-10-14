# sync.py
from pathlib import Path
import hashlib
import json
from datetime import datetime, timezone

def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def run(policy_dir: Path):
    if not policy_dir.exists():
        raise FileNotFoundError(f"policy dir not found: {policy_dir}")

    files = sorted([p for p in policy_dir.rglob("*") if p.is_file()])
    items = [{"path": str(f.relative_to(policy_dir.parent)), "sha256": _sha256(f)} for f in files]

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(policy_dir),
        "files": items
    }
    out = policy_dir.parent / "bundle.manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out