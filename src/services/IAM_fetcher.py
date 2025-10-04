# src/services/IAM_fetcher.py
from __future__ import annotations

from typing import Optional, List
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.models.IAM import PolicySummary, Inventory, Pagination


class FetchError(RuntimeError):
    """Raised when fetching IAM policies fails in a user-visible way."""


def _iso8601_utc(dt: datetime) -> str:
    """Normalize datetimes to ISO8601 UTC (e.g., '2025-10-03T19:02:11Z')."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_summary(item: dict) -> PolicySummary:
    """Map one ListPolicies item to PolicySummary (minimal fields only)."""
    update = item.get("UpdateDate")
    update_iso = _iso8601_utc(update) if isinstance(update, datetime) else str(update or "")
    return PolicySummary(
        arn=item["Arn"],
        name=item["PolicyName"],
        id=item["PolicyId"],
        path=item.get("Path", "/"),
        is_attachable=bool(item.get("IsAttachable", True)),
        default_version_id=item["DefaultVersionId"],
        update_date=update_iso,
    )


def collect_policies(
    profile: Optional[str] = None,
    region: Optional[str] = None,
    *,
    # "All" | "AWS" | "Local"
    scope: str = "All",
    only_attached: bool = False,
    page_size: int = 100,
    max_items: Optional[int] = None,
) -> Inventory:
    """
    Connect with the given profile/region and return an Inventory of IAM policies.
    - Uses IAM ListPolicies paginator.
    - Builds minimal PolicySummary list (no policy document).
    """
    try:
        # Session & clients
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region
        session = boto3.Session(**session_kwargs)

        iam = session.client("iam")
        sts = session.client("sts")

        # account id & retrieval time
        account_id = sts.get_caller_identity()["Account"]
        retrieved_at = _iso8601_utc(datetime.now(timezone.utc))

        # paginate ListPolicies
        paginator = iam.get_paginator("list_policies")
        pagination_config = {"PageSize": page_size} if page_size else {}
        page_iterator = paginator.paginate(
            Scope=scope, OnlyAttached=only_attached, PaginationConfig=pagination_config
        )

        summaries: List[PolicySummary] = []
        pages_count = 0

        for page in page_iterator:
            pages_count += 1
            for item in page.get("Policies", []):
                summaries.append(_build_summary(item))
                if max_items is not None and len(summaries) >= max_items:
                    # stop early
                    pagination = Pagination(pages=pages_count, page_size=page_size or 0)
                    return Inventory(
                        account_id=account_id,
                        retrieved_at=retrieved_at,
                        policies=summaries,
                        pagination=pagination,
                    )

        pagination = Pagination(pages=pages_count, page_size=page_size or 0)
        return Inventory(
            account_id=account_id,
            retrieved_at=retrieved_at,
            policies=summaries,
            pagination=pagination,
        )

    except (ClientError, BotoCoreError) as e:
        raise FetchError(f"Failed to list IAM policies: {e}") from e
