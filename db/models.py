from sqlalchemy import (
    Column, String, Text, Enum, Integer, ForeignKey, DateTime, JSON
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime, timezone


Base = declarative_base()

def gen_uuid():
    return str(uuid.uuid4())

class CloudGuardrail(Base):
    __tablename__ = "cloud_guardrails"
    id = Column(String, primary_key=True, default=gen_uuid)
    cloud_provider = Column(Enum("AWS", "Azure", "GCP", name="cloud_provider_enum"), nullable=False)
    type = Column(Enum("SCP", "IAM", "ConfigRule", "OrgPolicy", name="guardrail_type_enum"), nullable=False)
    name = Column(Text, nullable=False)
    raw_document = Column(JSON, nullable=False)
    hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    opa_policies = relationship("OpaPolicy", back_populates="guardrail")


class OpaPolicy(Base):
    __tablename__ = "opa_policies"
    id = Column(String, primary_key=True, default=gen_uuid)
    guardrail_id = Column(String, ForeignKey("cloud_guardrails.id"))
    policy_name = Column(Text, nullable=False)
    rego_code = Column(Text, nullable=False)
    version = Column(Integer, default=1)
    status = Column(Enum("active", "deprecated", "stale", name="policy_status_enum"), default="active")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    guardrail = relationship("CloudGuardrail", back_populates="opa_policies")


class PolicyPack(Base):
    __tablename__ = "policy_packs"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(Text, nullable=False)
    opa_policy_ids = Column(ARRAY(String))  # if your DB supports ARRAY
    pipeline_target = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class SyncEvent(Base):
    __tablename__ = "sync_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    guardrail_id = Column(String, ForeignKey("cloud_guardrails.id"))
    opa_policy_id = Column(String, ForeignKey("opa_policies.id"))
    status = Column(Enum("success", "failure", "warning", name="sync_status_enum"), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))