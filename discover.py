# discover.py
from pathlib import Path
from datetime import datetime, timezone
import os
import json

def run(
    output_path: Path,
    profile: str | None = None,
    region: str = "us-east-1",
    mock: bool = False,
    strict: bool = False,
) -> Path:
    """
    Discover Guardrails:
      - mock=True  : Always use local mock data, never access AWS.
      - strict=True: Raise error immediately if real AWS call fails (no fallback to mock).
      - Default    : Try real AWS call first; if it fails, fall back to mock to keep the pipeline running.
    Output: data/guardrails.json
    """

    # --- Helper function: write JSON output ---
    def _write(payload: dict) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_path

    # --- Unified payload structure (compatible with translate.py) ---
    def _aws_payload(scps: list, source="aws") -> dict:
        return {
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "aws": {
                "region": region,
                "scps": scps,
                "iam_policies": [],
                "config_rules": [],
            },
        }

    def _mock_payload(source="mock (forced)") -> dict:
        # Minimal mock payload, sufficient to drive translate/sync steps
        return _aws_payload(
            scps=[{"name": "DenyPublicEC2", "effect": "deny_public_ingress"}],
            source=source,
        )

    # --- Pure mock mode: never import boto3, never access the network ---
    if mock:
        return _write(_mock_payload("mock (forced)"))

    # --- Real AWS call (fallback to mock if not in strict mode) ---
    try:
        if profile:
            os.environ["AWS_PROFILE"] = profile
        if region:
            os.environ["AWS_DEFAULT_REGION"] = region

        # Lazy import to avoid boto dependency when in mock mode
        from src.services.SCP_fetcher import SCPFetcher

        fetcher = SCPFetcher(config={"profile": profile, "region": region})

        scps = fetcher.fetch_scp()

        return _write(_aws_payload(scps, source="aws"))

    except Exception as e:
        if strict:
            # In strict mode, raise immediately so CI fails
            raise
        # In non-strict mode, fall back to mock to keep pipeline running
        return _write(_mock_payload(source=f"mock ({type(e).__name__})"))