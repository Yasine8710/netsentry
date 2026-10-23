from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.detectors.base import Finding
from app.models.tables import (
    ALERT_STATUSES,
    SEVERITY_ORDER,
    Alert,
    AlertUpdate,
    utcnow,
)

MAX_NOTE_LEN = 4000
MAX_PAGE_SIZE = 200


class AlertNotFoundError(LookupError):
    pass


class AlertValidationError(ValueError):
    pass


@dataclass(slots=True)
class Page:
    items: list
    total: int
    page: int
    page_size: int


class AlertService:
    def __init__(self, session: Session) -> None:
        self.s = session

    def create_from_findings(self, analysis_id: str, findings: list[Finding]) -> list[Alert]:
        alerts = [
            Alert(
                analysis_id=analysis_id,
                rule_id=f.rule_id,
                severity=f.severity.value,
                severity_rank=SEVERITY_ORDER.index(f.severity.value),
                title=f.title[:300],
                first_seen=f.first_seen,
                last_seen=f.last_seen,
                src_ips=f.src_ips,
                dst_ips=f.dst_ips,
                evidence=f.evidence,
                explanation=f.explanation,
                why_suspicious=f.why_suspicious,
                benign_explanations=f.benign_explanations,
                recommended_steps=f.recommended_steps,
                confidence=f.confidence,
                confidence_label=f.confidence_label,
                fingerprint=f.fingerprint,
            )
            for f in findings
        ]
        self.s.add_all(alerts)
        self.s.flush()
        return alerts

    def get(self, alert_id: str) -> Alert:
        alert = self.s.get(Alert, alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)
        return alert

    def list(
        self,
        *,
        analysis_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        q: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> Page:
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        conds = []
        if analysis_id:
            conds.append(Alert.analysis_id == analysis_id)
        if severity:
            conds.append(Alert.severity == severity)
        if status:
            conds.append(Alert.status == status)
        if rule_id:
            conds.append(Alert.rule_id == rule_id)
        if q:
            like = f"%{q.replace('%', r'\%').replace('_', r'\_')}%"
            conds.append(Alert.title.ilike(like, escape="\\"))
        total = self.s.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
        rows = self.s.scalars(
            select(Alert)
            .where(*conds)
            .order_by(
                Alert.severity_rank.desc(), Alert.first_seen.is_(None), Alert.first_seen, Alert.id
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        return Page(list(rows), total, page, page_size)

    def counts_by_severity(self, analysis_id: str | None = None) -> dict[str, int]:
        stmt = select(Alert.severity, func.count()).group_by(Alert.severity)
        if analysis_id:
            stmt = stmt.where(Alert.analysis_id == analysis_id)
        found = dict(self.s.execute(stmt).all())
        return {sev: found.get(sev, 0) for sev in SEVERITY_ORDER}

    def update(self, alert_id: str, *, status: str | None = None, note: str | None = None) -> Alert:
        alert = self.get(alert_id)
        if status is None and note is None:
            raise AlertValidationError("Provide a status and/or a note.")
        if status is not None and status not in ALERT_STATUSES:
            raise AlertValidationError(f"Invalid status. Allowed: {', '.join(ALERT_STATUSES)}.")
        if note is not None:
            note = note.strip()
            if not note:
                raise AlertValidationError("Note must not be empty.")
            if len(note) > MAX_NOTE_LEN:
                raise AlertValidationError(f"Note too long (max {MAX_NOTE_LEN} characters).")
        if status is not None and status != alert.status:
            self.s.add(
                AlertUpdate(
                    alert_id=alert.id,
                    kind="status_change",
                    old_status=alert.status,
                    new_status=status,
                )
            )
            alert.status = status
        if note is not None:
            self.s.add(AlertUpdate(alert_id=alert.id, kind="note", note=note))
        alert.updated_at = utcnow()
        self.s.commit()
        self.s.refresh(alert)
        return alert
