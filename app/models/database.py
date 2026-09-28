import json
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import Column, String, Text, DateTime, Integer, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from app.config import settings

Base = declarative_base()

class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    source = Column(String(64), default="SIEM")
    description = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    username = Column(String(128), nullable=True)
    status = Column(String(32), default="RECEIVED")  # RECEIVED, BLOCKED, COMPLETED, PENDING_APPROVAL
    severity = Column(String(32), nullable=True)
    category = Column(String(64), nullable=True)
    summary_report = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), index=True, nullable=False)
    event_type = Column(String(64), nullable=False)  # GUARD_SCAN, TOOL_BLOCKED, APPROVAL_REQUESTED, etc.
    actor = Column(String(64), nullable=False)  # GUARD_LAYER, AGENT, ANALYST
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def details(self) -> Dict[str, Any]:
        try:
            return json.loads(self.details_json)
        except Exception:
            return {"raw": self.details_json}

    @details.setter
    def details(self, val: Dict[str, Any]):
        self.details_json = json.dumps(val)

class ApprovalGateRecord(Base):
    __tablename__ = "approval_gates"

    id = Column(String(64), primary_key=True, index=True)
    alert_id = Column(String(64), index=True, nullable=False)
    tool_name = Column(String(64), nullable=False)
    parameters_json = Column(Text, nullable=False, default="{}")
    status = Column(String(32), default="PENDING")  # PENDING, APPROVED, REJECTED
    analyst_id = Column(String(64), nullable=True)
    analyst_comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

# Engine & Session Setup
engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
