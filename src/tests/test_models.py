import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone

from src.models.db.models import (
    Base,
    SCP,
    CloudGuardrail,
    OpaPolicy,
    SyncEvent
)

@pytest.fixture(scope="function")
def db_session():
    """Creates a fresh in-memory SQLite database for each test."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


# --- SCP ---
def test_scp_insert_and_query(db_session):
    scp = SCP(
        policy_id="p-123",
        arn="arn:aws:org:policy/p-123",
        name="Test SCP",
        description="Test SCP policy",
        policy_type="SERVICE_CONTROL_POLICY",
        aws_managed=False,
        content='{"Statement": []}',
        policy_summary={"allowedActions": [], "deniedActions": []}
    )

    db_session.add(scp)
    db_session.commit()

    result = db_session.query(SCP).first()
    assert result.policy_id == "p-123"
    assert result.aws_managed is False
    assert isinstance(result.created_at, datetime)

# --- CloudGuardrail + OpaPolicy + SyncEvent (Relationship Test) ---
def test_guardrail_policy_sync_relationships(db_session):
    # Create a CloudGuardrail
    guardrail = CloudGuardrail(
        cloud_provider="AWS",
        type="SCP",
        name="Enforce S3 Encryption",
        raw_document={"Version": "2012-10-17", "Statement": []},
        hash="abc123"
    )

    db_session.add(guardrail)
    db_session.commit()

    # Create an OPA policy linked to the guardrail
    opa = OpaPolicy(
        guardrail_id=guardrail.id,
        policy_name="s3_encryption_policy",
        rego_code='package s3.encryption\nallow { input.Encrypted }',
        version=1,
        status="active"
    )

    db_session.add(opa)
    db_session.commit()

    # Verify relationship
    fetched_guardrail = db_session.query(CloudGuardrail).first()
    assert len(fetched_guardrail.opa_policies) == 1
    assert fetched_guardrail.opa_policies[0].policy_name == "s3_encryption_policy"

    # Create a SyncEvent for this OPA policy
    sync_event = SyncEvent(
        guardrail_id=guardrail.id,
        opa_policy_id=opa.id,
        status="success",
        details="Policy synced successfully"
    )

    db_session.add(sync_event)
    db_session.commit()

    # Verify SyncEvent persisted
    result = db_session.query(SyncEvent).first()
    assert result.status == "success"
    assert result.details == "Policy synced successfully"

    # Ensure timestamps are set
    assert isinstance(result.timestamp, datetime)
    assert isinstance(fetched_guardrail.created_at, datetime)
    assert isinstance(fetched_guardrail.updated_at, datetime)
    assert isinstance(fetched_guardrail.opa_policies[0].created_at, datetime)
    assert isinstance(fetched_guardrail.opa_policies[0].updated_at, datetime)
    # Verify full join relationships
    assert fetched_guardrail.opa_policies[0].guardrail.id == guardrail.id


# --- Combined smoke test (optional aggregate check) ---
def test_all_models_exist_and_queryable(db_session):
    """Ensures all tables exist and basic query returns empty list."""
    for model in [SCP, CloudGuardrail, OpaPolicy, SyncEvent]:
        results = db_session.query(model).all()
        assert isinstance(results, list)
