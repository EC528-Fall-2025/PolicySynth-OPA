# src/models/IAM.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Any, Dict
import json


# Minimal IAM policy information returned from ListPolicies
@dataclass(frozen=True)
class PolicySummary:
    """Fields straight from ListPolicies you need for a structured output."""
    arn: str                 # item["Arn"]
    name: str                # item["PolicyName"]
    id: str                  # item["PolicyId"]
    path: str                # item.get("Path", "/")
    is_attachable: bool      # item.get("IsAttachable", True)
    default_version_id: str  # item["DefaultVersionId"]
    update_date: str         # ISO8601 string (normalize in fetcher)


# Pagination metadata for policy listing
@dataclass(frozen=True)
class Pagination:
    pages: int
    page_size: int


# Full IAM policy inventory returned by the CLI
@dataclass(frozen=True)
class Inventory:
    """Top-level object CLI prints/writes."""
    account_id: str          # from STS get-caller-identity
    retrieved_at: str
    policies: List[PolicySummary] = field(default_factory=list)
    pagination: Pagination = field(default_factory=lambda: Pagination(0, 0))


# ---- Helpers ----
# Convert a dataclass object into a Python dict
def to_dict(obj: Any) -> Dict[str, Any]:
    return asdict(obj)


# Convert a dataclass object into a JSON string
def to_json(obj: Any, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(asdict(obj), ensure_ascii=False, indent=2)
    return json.dumps(asdict(obj), ensure_ascii=False, separators=(",", ":"))


__all__ = ["PolicySummary", "Pagination", "Inventory", "to_dict", "to_json"]
