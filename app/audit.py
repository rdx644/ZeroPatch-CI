"""Durable, privacy-minimised audit trail for scans and remediation drafts."""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="anonymous")
    source_name: Mapped[str] = mapped_column(String(160), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    patch_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")


class AuditStore:
    def __init__(self, database_url: str | None = None, required: bool | None = None) -> None:
        url = database_url or os.getenv("DATABASE_URL")
        self.required = required if required is not None else os.getenv("ZEROPATCH_AUDIT_REQUIRED") == "1"
        self.engine = None
        if url:
            if url.startswith("postgres://"):
                url = "postgresql+psycopg://" + url.removeprefix("postgres://")
            elif url.startswith("postgresql://"):
                url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
            self.engine = create_engine(url, pool_pre_ping=True, future=True)

    def initialize(self) -> bool:
        if not self.engine:
            return not self.required
        try:
            Base.metadata.create_all(self.engine)
            return True
        except SQLAlchemyError:
            logger.exception("Audit database initialization failed")
            return False

    def ready(self) -> bool:
        if not self.engine:
            return not self.required
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            logger.exception("Audit database readiness check failed")
            return False

    def record(self, action: str, actor: str, source_name: str, finding_count: int, patch_id: str | None = None, detail: str = "") -> bool:
        if not self.engine:
            return not self.required
        event = AuditEvent(
            id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            action=action[:32],
            actor=actor[:128],
            source_name=source_name[:160],
            finding_count=max(0, finding_count),
            patch_id=patch_id,
            detail=detail[:2000],
        )
        try:
            with Session(self.engine) as session:
                session.add(event)
                session.commit()
            return True
        except SQLAlchemyError:
            logger.exception("Audit event persistence failed")
            return False

    def recent(self, limit: int = 50) -> list[dict[str, object]]:
        if not self.engine:
            return []
        bounded_limit = min(max(limit, 1), 100)
        try:
            with Session(self.engine) as session:
                events = session.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(bounded_limit)).all()
            return [{
                "id": event.id,
                "created_at": event.created_at.isoformat(),
                "action": event.action,
                "actor": event.actor,
                "source_name": event.source_name,
                "finding_count": event.finding_count,
                "patch_id": event.patch_id,
            } for event in events]
        except SQLAlchemyError:
            logger.exception("Audit event query failed")
            return []