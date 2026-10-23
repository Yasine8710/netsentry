from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

UtcDatetime = Annotated[datetime, PlainSerializer(lambda d: d.isoformat() + "Z", return_type=str)]

Status = Literal["new", "investigating", "resolved", "false_positive"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Pagination(BaseModel):
    total: int
    page: int
    page_size: int


class SummaryOut(ORM):
    packets: int
    bytes: int
    first_ts: float | None
    last_ts: float | None
    duration_s: float | None
    unique_src_ips: int
    unique_dst_ips: int
    data: dict


class AnalysisOut(ORM):
    id: str
    filename: str
    file_format: str | None
    file_size: int
    status: str
    error: str | None
    is_demo: bool
    created_at: UtcDatetime
    completed_at: UtcDatetime | None
    parse_stats: dict | None
    notes: list | None
    alert_counts: dict[str, int] = Field(default_factory=dict)
    summary: SummaryOut | None = None


class AnalysisListItem(ORM):
    id: str
    filename: str
    status: str
    is_demo: bool
    created_at: UtcDatetime
    packets: int = 0
    bytes: int = 0
    alert_total: int = 0


class AnalysisPage(Pagination):
    items: list[AnalysisListItem]


class AlertUpdateOut(ORM):
    id: int
    kind: str
    old_status: str | None
    new_status: str | None
    note: str | None
    created_at: UtcDatetime


class AlertOut(ORM):
    id: str
    analysis_id: str
    rule_id: str
    severity: str
    title: str
    first_seen: float | None
    last_seen: float | None
    src_ips: list[str]
    dst_ips: list[str]
    confidence: float
    confidence_label: str
    status: str
    created_at: UtcDatetime
    updated_at: UtcDatetime


class AlertDetailOut(AlertOut):
    evidence: dict
    explanation: str
    why_suspicious: str
    benign_explanations: list[str]
    recommended_steps: list[str]
    updates: list[AlertUpdateOut]
    rule: dict | None = None


class AlertPage(Pagination):
    items: list[AlertOut]


class AlertPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Status | None = None
    note: str | None = Field(None, max_length=4000)


class PacketOut(ORM):
    seq: int
    ts: float | None
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    length: int
    tcp_flags: int | None
    info: str | None


class PacketPage(Pagination):
    items: list[PacketOut]
    packets_total: int
    packets_stored: int
    truncated: bool
