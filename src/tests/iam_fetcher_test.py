# tests/test_iam_fetcher.py
from __future__ import annotations

import os, sys
from datetime import datetime, timezone
from typing import List, Dict, Any

import pytest
from botocore.exceptions import BotoCoreError

sys.path.insert(0, os.path.abspath("."))

from src.services.IAM_fetcher import IAMPolicyFetcher, FetchError


# -------- fakes --------

class FakePaginator:
    def __init__(self, pages: List[Dict[str, Any]]):
        self._pages = pages
        self.seen_kwargs = None

    def paginate(self, **kwargs):
        self.seen_kwargs = kwargs
        for p in self._pages:
            yield p


class FakeIAM:
    def __init__(self, pages):
        self._pages = pages
        self.last_paginator = None

    def get_paginator(self, name: str):
        assert name == "list_policies"
        self.last_paginator = FakePaginator(self._pages)
        return self.last_paginator


class FakeSTS:
    def __init__(self, account_id="123456789012", raise_error=False):
        self._aid, self._err = account_id, raise_error

    def get_caller_identity(self):
        if self._err:
            raise BotoCoreError()
        return {"Account": self._aid}


def make_fake_session_factory(pages, raise_sts=False):
    class _FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name: str):
            if name == "iam":
                return FakeIAM(pages)
            if name == "sts":
                return FakeSTS(raise_error=raise_sts)
            raise AssertionError(f"unexpected client {name}")

    def _factory(**kwargs):
        return _FakeSession(**kwargs)

    return _factory


def _item(i: int):
    return {
        "Arn": f"arn:aws:iam::aws:policy/Demo{i}",
        "PolicyName": f"Demo{i}",
        "PolicyId": f"PID{i}",
        "Path": "/",
        "DefaultVersionId": "v1",
        "IsAttachable": True,
        "UpdateDate": datetime(2025, 1, 1, tzinfo=timezone.utc),
    }


# -------- tests --------

def test_single_page():
    pages = [{"Policies": [_item(1), _item(2)]}]
    fetcher = IAMPolicyFetcher(session_factory=make_fake_session_factory(pages))
    inv = fetcher.collect_policies(page_size=50)

    assert inv.account_id == "123456789012"
    assert inv.pagination.pages == 1 and inv.pagination.page_size == 50
    assert len(inv.policies) == 2 and inv.policies[0].name == "Demo1"
    assert inv.policies[0].update_date.endswith("Z")


def test_multi_page_with_cap():
    pages = [{"Policies": [_item(1), _item(2)]}, {"Policies": [_item(3), _item(4)]}, ]
    fetcher = IAMPolicyFetcher(session_factory=make_fake_session_factory(pages))
    inv = fetcher.collect_policies(page_size=2, max_items=3)

    assert inv.pagination.pages == 2 and inv.pagination.page_size == 2
    assert [p.name for p in inv.policies] == ["Demo1", "Demo2", "Demo3"]


def test_error_path():
    pages = [{"Policies": []}]
    fetcher = IAMPolicyFetcher(session_factory=make_fake_session_factory(pages, raise_sts=True))
    with pytest.raises(FetchError):
        fetcher.collect_policies()
