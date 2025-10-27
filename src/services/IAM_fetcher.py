# src/services/IAM_fetcher.py
from __future__ import annotations

from typing import Optional, Callable, List
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.models.IAM import PolicySummary, Inventory, Pagination


# Custom error for handling IAM policy fetch failures
class FetchError(RuntimeError):
    """Raised when fetching IAM policies fails in a user-visible way."""


# Convert datetime to ISO8601 UTC string format
def _iso8601_utc(dt: datetime) -> str:
    """Normalize datetimes to ISO8601 UTC (e.g., '2025-10-03T19:02:11Z')."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Build a PolicySummary object from a single IAM ListPolicies response item
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


# Use for injection in the future
class IAMPolicyFetcher:

    # Initialize IAMPolicyFetcher with AWS session, IAM and STS clients
    def __init__(
        self,
        *,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        session_factory: Callable[..., boto3.Session] = boto3.Session,
    ) -> None:
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region

        self._session = session_factory(**session_kwargs)
        self._iam = self._session.client("iam")
        self._sts = self._session.client("sts")

    # Collect IAM policies and return a structured Inventory object
    def collect_policies(
        self,
        *,
        scope: str = "All",            # "All" | "AWS" | "Local"
        only_attached: bool = False,
        page_size: int = 100,
        max_items: Optional[int] = None,
    ) -> Inventory:
        """
        List IAM policies using the paginator and return a structured Inventory.
        """
        try:
            # account id & retrieval time
            account_id = self._sts.get_caller_identity()["Account"]
            retrieved_at = _iso8601_utc(datetime.now(timezone.utc))

            # paginator with explicit kwargs (mirrors real boto3 usage)
            paginator = self._iam.get_paginator("list_policies")
            kwargs = {"Scope": scope, "OnlyAttached": only_attached}
            if page_size:
                kwargs["PaginationConfig"] = {"PageSize": page_size}

            page_iterator = paginator.paginate(**kwargs)

            summaries: List[PolicySummary] = []
            pages_count = 0

            for page in page_iterator:
                pages_count += 1
                for item in page.get("Policies", []):
                    summaries.append(_build_summary(item))
                    if max_items is not None and len(summaries) >= max_items:
                        return Inventory(
                            account_id=account_id,
                            retrieved_at=retrieved_at,
                            policies=summaries,
                            pagination=Pagination(pages=pages_count, page_size=page_size or 0),
                        )

            return Inventory(
                account_id=account_id,
                retrieved_at=retrieved_at,
                policies=summaries,
                pagination=Pagination(pages=pages_count, page_size=page_size or 0),
            )

        except (ClientError, BotoCoreError) as e:
            raise FetchError(f"Failed to list IAM policies: {e}") from e
