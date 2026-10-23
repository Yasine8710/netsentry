"""ORM tables. No raw packet payloads are ever stored."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC (SQLite drops tzinfo); serialized with a 'Z' suffix by the API layer."""
    return datetime.now(UTC).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    """One uploaded capture and its processing state."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(String(255))  # display only, sanitized
    file_format: Mapped[str | None] = mapped_column(String(16))
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    completed_at: Mapped[datetime | None]
    parse_stats: Mapped[dict | None] = mapped_column(JSON)
    detection_config: Mapped[dict | None] = mapped_column(JSON)  # config snapshot used
    notes: Mapped[list | None] = mapped_column(JSON)

    summary: Mapped["AnalysisSummary | None"] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", uselist=False
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    traffic_stats: Mapped[list["TrafficStat"]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )
    packets: Mapped[list["PacketRecord"]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )


class AnalysisSummary(Base):
    __tablename__ = "analysis_summaries"

    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True
    )
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    first_ts: Mapped[float | None] = mapped_column(Float)
    last_ts: Mapped[float | None] = mapped_column(Float)
    duration_s: Mapped[float | None] = mapped_column(Float)
    unique_src_ips: Mapped[int] = mapped_column(Integer, default=0)
    unique_dst_ips: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict] = mapped_column(JSON)  # full aggregator summary

    analysis: Mapped[Analysis] = relationship(back_populates="summary")


class TrafficStat(Base):
    """Aggregated rows for cross-analysis dashboards (kind: protocol|src_ip|dst_ip|...)."""

    __tablename__ = "traffic_stats"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))
    key: Mapped[str] = mapped_column(String(64))
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (Index("ix_traffic_stats_lookup", "analysis_id", "kind"),)


class PacketRecord(Base):
    """Per-packet metadata (capped per analysis) for search/filter. Headers only."""

    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[float | None] = mapped_column(Float)
    src: Mapped[str] = mapped_column(String(45))
    dst: Mapped[str] = mapped_column(String(45))
    proto: Mapped[str] = mapped_column(String(8))
    sport: Mapped[int | None]
    dport: Mapped[int | None]
    length: Mapped[int] = mapped_column(Integer)
    tcp_flags: Mapped[int | None]
    info: Mapped[str | None] = mapped_column(String(300))  # e.g. DNS qname

    __table_args__ = (
        Index("ix_packets_analysis_seq", "analysis_id", "seq"),
        Index("ix_packets_analysis_src", "analysis_id", "src"),
        Index("ix_packets_analysis_dst", "analysis_id", "dst"),
    )


SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(300))
    first_seen: Mapped[float | None] = mapped_column(Float)
    last_seen: Mapped[float | None] = mapped_column(Float)
    src_ips: Mapped[list] = mapped_column(JSON)
    dst_ips: Mapped[list] = mapped_column(JSON)
    evidence: Mapped[dict] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text)
    why_suspicious: Mapped[str] = mapped_column(Text)
    benign_explanations: Mapped[list] = mapped_column(JSON)
    recommended_steps: Mapped[list] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    confidence_label: Mapped[str] = mapped_column(String(8))
    fingerprint: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)

    analysis: Mapped[Analysis] = relationship(back_populates="alerts")
    updates: Mapped[list["AlertUpdate"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertUpdate.id"
    )


class AlertUpdate(Base):
    """Audit trail: status changes and analyst notes."""

    __tablename__ = "alert_updates"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # status_change | note
    old_status: Mapped[str | None] = mapped_column(String(16))
    new_status: Mapped[str | None] = mapped_column(String(16))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    alert: Mapped[Alert] = relationship(back_populates="updates")


class RuleMetadata(Base):
    __tablename__ = "rule_metadata"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    limitations: Mapped[list] = mapped_column(JSON)
    false_positive_notes: Mapped[str] = mapped_column(Text)
    parameters: Mapped[list] = mapped_column(JSON)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
