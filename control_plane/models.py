from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PublicationRow(Base):
    __tablename__ = "publications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repository: Mapped[str] = mapped_column(String(200), nullable=False)
    issue_number: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class CandidateRow(Base):
    __tablename__ = "candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    publication_id: Mapped[str] = mapped_column(ForeignKey("publications.id"), nullable=False, index=True)
    base_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    tree_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(160), nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class CandidateSourceRow(Base):
    __tablename__ = "candidate_sources"

    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("candidates.id"),
        primary_key=True,
    )
    bundle_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    quarantine_id: Mapped[str] = mapped_column(String(64), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    tree_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )


class CodexReviewDispatchRow(Base):
    __tablename__ = "codex_review_dispatches"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    publication_id: Mapped[str] = mapped_column(
        ForeignKey("publications.id"),
        nullable=False,
        index=True,
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_comment_id: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )


class EventRow(Base):
    __tablename__ = "publication_events"
    __table_args__ = (UniqueConstraint("publication_id", "sequence", name="uq_publication_event_sequence"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    publication_id: Mapped[str] = mapped_column(ForeignKey("publications.id"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class RemediationWorkPackageRow(Base):
    """Aggregate identity and issue-link index; the event ledger is authoritative."""

    __tablename__ = "remediation_work_packages"
    __table_args__ = (
        UniqueConstraint(
            "repository",
            "implementation_issue_number",
            name="uq_remediation_repository_issue",
        ),
        UniqueConstraint(
            "publication_id",
            "review_run_id",
            name="uq_remediation_publication_review_run",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    publication_id: Mapped[str] = mapped_column(
        ForeignKey("publications.id"),
        nullable=False,
        index=True,
    )
    repository: Mapped[str] = mapped_column(String(200), nullable=False)
    review_run_id: Mapped[str] = mapped_column(String(160), nullable=False)
    reviewed_head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    implementation_issue_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )


class RemediationEventRow(Base):
    __tablename__ = "remediation_events"
    __table_args__ = (
        UniqueConstraint(
            "work_package_id",
            "sequence",
            name="uq_remediation_event_sequence",
        ),
        UniqueConstraint(
            "work_package_id",
            "idempotency_key",
            name="uq_remediation_event_idempotency",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    work_package_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_work_packages.id"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class RemediationDispatchRow(Base):
    """Expiring coordination lease; the event log remains authoritative."""

    __tablename__ = "remediation_dispatches"

    work_package_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_work_packages.id"),
        primary_key=True,
    )
    artifact_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )


class WorkItemRow(Base):
    """Stable work-item identity; lifecycle is reconstructed from WorkItemEventRow."""

    __tablename__ = "work_items"
    __table_args__ = (
        UniqueConstraint(
            "repository",
            "issue_number",
            name="uq_work_item_repository_issue",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repository: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    issue_number: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_work_item_id: Mapped[str | None] = mapped_column(
        ForeignKey("work_items.id"),
        nullable=True,
        index=True,
    )
    required_for_parent: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    executable: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    context_version: Mapped[int] = mapped_column(Integer, nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )


class WorkDependencyRow(Base):
    """Materialized hard-dependency edge; creation is also recorded in the work ledger."""

    __tablename__ = "work_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "work_item_id",
            "depends_on_work_item_id",
            name="uq_work_dependency_edge",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    work_item_id: Mapped[str] = mapped_column(
        ForeignKey("work_items.id"),
        nullable=False,
        index=True,
    )
    depends_on_work_item_id: Mapped[str] = mapped_column(
        ForeignKey("work_items.id"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )


class WorkItemEventRow(Base):
    __tablename__ = "work_item_events"
    __table_args__ = (
        UniqueConstraint(
            "work_item_id",
            "sequence",
            name="uq_work_item_event_sequence",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_work_item_event_idempotency",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    work_item_id: Mapped[str] = mapped_column(
        ForeignKey("work_items.id"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class GitHubWebhookDeliveryRow(Base):
    """Durable GitHub delivery inbox; payloads are wake-up evidence, never authority."""

    __tablename__ = "github_webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    event_name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    action: Mapped[str | None] = mapped_column(String(80), nullable=True)
    repository: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    pull_request_number: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class ReviewWatchRow(Base):
    """Recoverable exact-head review watch projection derived from publication authority."""

    __tablename__ = "review_watches"

    publication_id: Mapped[str] = mapped_column(
        ForeignKey("publications.id"),
        primary_key=True,
    )
    repository: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    watched_head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    review_run_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(80), nullable=True)
    trigger_comment_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expected_actors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE")
    next_role: Mapped[str] = mapped_column(String(80), nullable=False, default="CONTROL_PLANE")
    next_action: Mapped[str] = mapped_column(String(80), nullable=False, default="WAIT_PROVIDER")
    last_delivery_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_reconciled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )
