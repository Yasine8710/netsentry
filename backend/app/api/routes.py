from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import get_session
from app.detectors.engine import DetectionEngine
from app.models.tables import (
    SEVERITY_ORDER,
    Alert,
    Analysis,
    AnalysisSummary,
    PacketRecord,
    TrafficStat,
)
from app.schemas.api import (
    AlertDetailOut,
    AlertOut,
    AlertPage,
    AlertPatch,
    AnalysisListItem,
    AnalysisOut,
    AnalysisPage,
    PacketOut,
    PacketPage,
)
from app.services.alert_service import (
    AlertNotFoundError,
    AlertService,
    AlertValidationError,
)
from app.services.analysis_service import AnalysisService, UploadError
from app.services.settings_service import (
    AppSettings,
    SettingsService,
    SettingsValidationError,
)

router = APIRouter(prefix="/api")
SessionDep = Annotated[Session, Depends(get_session)]
Page = Annotated[int, Query(ge=1, le=1_000_000)]
PageSize = Annotated[int, Query(ge=1, le=200)]
Severity = Literal["informational", "low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved", "false_positive"]


def _analysis_or_404(s: Session, analysis_id: str) -> Analysis:
    a = s.get(Analysis, analysis_id)
    if a is None:
        raise HTTPException(404, "Analysis not found.")
    return a


def _list_item(a: Analysis, s: Session) -> AnalysisListItem:
    summ = s.get(AnalysisSummary, a.id)
    total = s.scalar(select(func.count()).select_from(Alert).where(Alert.analysis_id == a.id))
    return AnalysisListItem(
        id=a.id,
        filename=a.filename,
        status=a.status,
        is_demo=a.is_demo,
        created_at=a.created_at,
        packets=summ.packets if summ else 0,
        bytes=summ.bytes if summ else 0,
        alert_total=total or 0,
    )


def _analysis_out(s: Session, a: Analysis) -> AnalysisOut:
    out = AnalysisOut.model_validate(a)
    out.alert_counts = AlertService(s).counts_by_severity(a.id)
    return out


# ---- analyses ----------------------------------------------------------------
@router.post("/analyses", response_model=AnalysisOut, status_code=201, tags=["analyses"])
def create_analysis(s: SessionDep, file: Annotated[UploadFile, File()]):
    """Upload a .pcap/.pcapng capture and analyze it synchronously."""
    try:
        a = AnalysisService(s).handle_upload(file.file, file.filename)
    except UploadError as exc:
        raise HTTPException(exc.status_code, exc.message) from exc
    return _analysis_out(s, a)


@router.post("/analyses/demo", response_model=AnalysisOut, status_code=201, tags=["analyses"])
def create_demo_analysis(s: SessionDep):
    """Analyze a built-in synthetic capture. The result is flagged `is_demo`."""
    return _analysis_out(s, AnalysisService(s).handle_demo())


@router.get("/analyses", response_model=AnalysisPage, tags=["analyses"])
def list_analyses(s: SessionDep, page: Page = 1, page_size: PageSize = 25):
    total = s.scalar(select(func.count()).select_from(Analysis)) or 0
    rows = s.execute(
        select(Analysis, AnalysisSummary.packets, AnalysisSummary.bytes)
        .outerjoin(AnalysisSummary, AnalysisSummary.analysis_id == Analysis.id)
        .order_by(Analysis.created_at.desc(), Analysis.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    alert_totals = dict(
        s.execute(select(Alert.analysis_id, func.count()).group_by(Alert.analysis_id)).all()
    )
    items = [
        AnalysisListItem(
            id=a.id,
            filename=a.filename,
            status=a.status,
            is_demo=a.is_demo,
            created_at=a.created_at,
            packets=packets or 0,
            bytes=nbytes or 0,
            alert_total=alert_totals.get(a.id, 0),
        )
        for a, packets, nbytes in rows
    ]
    return AnalysisPage(items=items, total=total, page=page, page_size=page_size)


@router.get("/analyses/{analysis_id}", response_model=AnalysisOut, tags=["analyses"])
def get_analysis(analysis_id: str, s: SessionDep):
    return _analysis_out(s, _analysis_or_404(s, analysis_id))


@router.delete("/analyses/{analysis_id}", status_code=204, tags=["analyses"])
def delete_analysis(analysis_id: str, s: SessionDep):
    if not AnalysisService(s).delete(analysis_id):
        raise HTTPException(404, "Analysis not found.")
    return Response(status_code=204)


@router.get("/analyses/{analysis_id}/traffic", response_model=PacketPage, tags=["analyses"])
def get_traffic(
    analysis_id: str,
    s: SessionDep,
    page: Page = 1,
    page_size: PageSize = 50,
    q: Annotated[str | None, Query(max_length=100)] = None,
    proto: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    src: Annotated[str | None, Query(max_length=45)] = None,
    dst: Annotated[str | None, Query(max_length=45)] = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
):
    """Paginated, filterable packet metadata (headers only; payloads are never stored)."""
    a = _analysis_or_404(s, analysis_id)
    conds = [PacketRecord.analysis_id == analysis_id]
    if proto:
        conds.append(PacketRecord.proto == proto)
    if src:
        conds.append(PacketRecord.src == src)
    if dst:
        conds.append(PacketRecord.dst == dst)
    if port is not None:
        conds.append((PacketRecord.sport == port) | (PacketRecord.dport == port))
    if q:
        like = f"%{q.replace('%', r'\%').replace('_', r'\_')}%"
        conds.append(
            PacketRecord.src.ilike(like, escape="\\")
            | PacketRecord.dst.ilike(like, escape="\\")
            | PacketRecord.info.ilike(like, escape="\\")
        )
    total = s.scalar(select(func.count()).select_from(PacketRecord).where(*conds)) or 0
    rows = s.scalars(
        select(PacketRecord)
        .where(*conds)
        .order_by(PacketRecord.seq)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    stats = a.parse_stats or {}
    packets_total = stats.get("packets_parsed", 0)
    stored = stats.get("packets_stored", 0)
    return PacketPage(
        items=[PacketOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        packets_total=packets_total,
        packets_stored=stored,
        truncated=stored < packets_total,
    )


@router.get("/analyses/{analysis_id}/alerts", response_model=AlertPage, tags=["alerts"])
def analysis_alerts(
    analysis_id: str,
    s: SessionDep,
    page: Page = 1,
    page_size: PageSize = 25,
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
):
    _analysis_or_404(s, analysis_id)
    res = AlertService(s).list(
        analysis_id=analysis_id,
        severity=severity,
        status=status,
        rule_id=rule_id,
        page=page,
        page_size=page_size,
    )
    return AlertPage(items=res.items, total=res.total, page=res.page, page_size=res.page_size)


# ---- alerts ----------------------------------------------------------------
@router.get("/alerts", response_model=AlertPage, tags=["alerts"])
def list_alerts(
    s: SessionDep,
    page: Page = 1,
    page_size: PageSize = 25,
    analysis_id: Annotated[str | None, Query(max_length=64)] = None,
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
):
    res = AlertService(s).list(
        analysis_id=analysis_id,
        severity=severity,
        status=status,
        rule_id=rule_id,
        q=q,
        page=page,
        page_size=page_size,
    )
    return AlertPage(items=res.items, total=res.total, page=res.page, page_size=res.page_size)


def _alert_detail(s: Session, alert: Alert) -> AlertDetailOut:
    out = AlertDetailOut.model_validate(alert)
    out.rule = next(
        (m for m in DetectionEngine().rules_metadata() if m["id"] == alert.rule_id), None
    )
    return out


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut, tags=["alerts"])
def get_alert(alert_id: str, s: SessionDep):
    try:
        return _alert_detail(s, AlertService(s).get(alert_id))
    except AlertNotFoundError as exc:
        raise HTTPException(404, "Alert not found.") from exc


@router.patch("/alerts/{alert_id}", response_model=AlertDetailOut, tags=["alerts"])
def patch_alert(alert_id: str, body: AlertPatch, s: SessionDep):
    """Update an alert's status and/or append an analyst note."""
    try:
        return _alert_detail(
            s, AlertService(s).update(alert_id, status=body.status, note=body.note)
        )
    except AlertNotFoundError as exc:
        raise HTTPException(404, "Alert not found.") from exc
    except AlertValidationError as exc:
        raise HTTPException(422, str(exc)) from exc


# ---- rules, settings, overview ------------------------------------------------
@router.get("/rules", tags=["rules"])
def list_rules(s: SessionDep):
    """Rule documentation with the currently effective parameters."""
    cfg = SettingsService(s).detection_config()
    return DetectionEngine(config=cfg).rules_metadata()


@router.get("/settings", response_model=AppSettings, tags=["settings"])
def get_settings_endpoint(s: SessionDep):
    return SettingsService(s).get()


@router.put("/settings", response_model=AppSettings, tags=["settings"])
def put_settings(body: dict, s: SessionDep):
    try:
        return SettingsService(s).update(body)
    except SettingsValidationError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/overview", tags=["overview"])
def overview(s: SessionDep, include_demo: bool = True):
    """Aggregates over stored analyses. `includes_demo` states whether demo data is mixed in."""
    base = select(Analysis.id).where(Analysis.status == "completed")
    if not include_demo:
        base = base.where(Analysis.is_demo.is_(False))
    ids = list(s.scalars(base))
    demo_count = (
        s.scalar(
            select(func.count()).select_from(Analysis).where(Analysis.id.in_(ids), Analysis.is_demo)
        )
        if ids
        else 0
    )
    empty = {
        "has_data": False,
        "includes_demo": False,
        "demo_analyses": 0,
        "analyses": 0,
        "packets": 0,
        "bytes": 0,
        "unique_src_ips": 0,
        "unique_dst_ips": 0,
        "unique_ips_basis": "sum_of_per_capture",
        "protocols": [],
        "alerts_by_severity": {k: 0 for k in SEVERITY_ORDER},
        "traffic_over_time": None,
        "top_ips": [],
        "recent_alerts": [],
        "recent_analyses": [],
    }
    if not ids:
        return empty
    tot = s.execute(
        select(
            func.coalesce(func.sum(AnalysisSummary.packets), 0),
            func.coalesce(func.sum(AnalysisSummary.bytes), 0),
            func.coalesce(func.sum(AnalysisSummary.unique_src_ips), 0),
            func.coalesce(func.sum(AnalysisSummary.unique_dst_ips), 0),
        ).where(AnalysisSummary.analysis_id.in_(ids))
    ).one()
    protocols = [
        {"protocol": k, "packets": p, "bytes": b}
        for k, p, b in s.execute(
            select(TrafficStat.key, func.sum(TrafficStat.packets), func.sum(TrafficStat.bytes))
            .where(TrafficStat.analysis_id.in_(ids), TrafficStat.kind == "protocol")
            .group_by(TrafficStat.key)
            .order_by(func.sum(TrafficStat.packets).desc(), TrafficStat.key)
        )
    ]
    ip_rows: dict[str, dict] = {}
    for key, _kind, p, b in s.execute(
        select(
            TrafficStat.key,
            TrafficStat.kind,
            func.sum(TrafficStat.packets),
            func.sum(TrafficStat.bytes),
        )
        .where(TrafficStat.analysis_id.in_(ids), TrafficStat.kind.in_(["src_ip", "dst_ip"]))
        .group_by(TrafficStat.key, TrafficStat.kind)
    ):
        row = ip_rows.setdefault(key, {"ip": key, "packets": 0, "bytes": 0})
        row["packets"] += p
        row["bytes"] += b
    top_ips = sorted(ip_rows.values(), key=lambda r: (-r["packets"], r["ip"]))[:10]

    latest = s.scalars(
        select(Analysis).where(Analysis.id.in_(ids)).order_by(Analysis.created_at.desc()).limit(1)
    ).one()
    latest_summary = s.get(AnalysisSummary, latest.id)
    series = (latest_summary.data or {}).get("time_series") if latest_summary else None

    recent_alerts = s.scalars(
        select(Alert)
        .where(Alert.analysis_id.in_(ids))
        .order_by(Alert.created_at.desc(), Alert.severity_rank.desc(), Alert.id)
        .limit(8)
    ).all()
    sev_rows = dict(
        s.execute(
            select(Alert.severity, func.count())
            .where(Alert.analysis_id.in_(ids))
            .group_by(Alert.severity)
        ).all()
    )
    recent = s.scalars(
        select(Analysis).where(Analysis.id.in_(ids)).order_by(Analysis.created_at.desc()).limit(5)
    ).all()
    return {
        "has_data": True,
        "includes_demo": bool(demo_count),
        "demo_analyses": demo_count,
        "analyses": len(ids),
        "packets": tot[0],
        "bytes": tot[1],
        "unique_src_ips": tot[2],
        "unique_dst_ips": tot[3],
        "unique_ips_basis": "sum_of_per_capture",
        "protocols": protocols,
        "alerts_by_severity": {k: sev_rows.get(k, 0) for k in SEVERITY_ORDER},
        "traffic_over_time": {
            "analysis_id": latest.id,
            "filename": latest.filename,
            "is_demo": latest.is_demo,
            "series": series,
        },
        "top_ips": top_ips,
        "recent_alerts": [
            AlertOut.model_validate(a).model_dump(mode="json") for a in recent_alerts
        ],
        "recent_analyses": [_list_item(a, s).model_dump(mode="json") for a in recent],
    }
