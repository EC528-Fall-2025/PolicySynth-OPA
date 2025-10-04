# src/models/IAM.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Any, Dict
import json


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


@dataclass(frozen=True)
class Pagination:
    pages: int
    page_size: int


@dataclass(frozen=True)
class Inventory:
    """Top-level object CLI prints/writes."""
    account_id: str          # from STS get-caller-identity
    retrieved_at: str
    policies: List[PolicySummary] = field(default_factory=list)
    pagination: Pagination = field(default_factory=lambda: Pagination(0, 0))


# ---- Helpers ----

def to_dict(obj: Any) -> Dict[str, Any]:
    return asdict(obj)


def to_json(obj: Any, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(asdict(obj), ensure_ascii=False, indent=2)
    return json.dumps(asdict(obj), ensure_ascii=False, separators=(",", ":"))


__all__ = ["PolicySummary", "Pagination", "Inventory", "to_dict", "to_json"]
