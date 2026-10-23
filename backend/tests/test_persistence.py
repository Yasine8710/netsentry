import pytest
from sqlalchemy import select, text

from app.core.db import SCHEMA_VERSION, init_db
from app.detectors.base import Finding, Severity
from app.models.tables import Alert, AlertUpdate, Analysis, RuleMetadata
from app.services.alert_service import (
    AlertNotFoundError,
    AlertService,
    AlertValidationError,
)
from app.services.settings_service import (
    SettingsService,
    SettingsValidationError,
    sync_rule_metadata,
)


def finding(key="k", sev=Severity.MEDIUM, first=10.0, rule="port_scan", title="t"):
    return Finding(
        rule,
        sev,
        title,
        first,
        first + 1,
        ["1.1.1.1"],
        ["2.2.2.2"],
        {"n": 1},
        "expl",
        "why",
        ["benign"],
        ["step"],
        0.6,
        key=key,
    )


@pytest.fixture
def analysis(session):
    a = Analysis(filename="x.pcap", status="completed")
    session.add(a)
    session.commit()
    return a


def test_create_alerts_unique_ids(session, analysis):
    svc = AlertService(session)
    alerts = svc.create_from_findings(analysis.id, [finding("a"), finding("b")])
    session.commit()
    assert len({a.id for a in alerts}) == 2 and all(a.status == "new" for a in alerts)
    assert alerts[0].confidence_label == "medium"


def test_status_and_note_persist_across_sessions(session, analysis, factory):
    svc = AlertService(session)
    (alert,) = svc.create_from_findings(analysis.id, [finding()])
    session.commit()
    svc.update(alert.id, status="investigating", note="  checking firewall  ")
    with factory() as s2:
        a = AlertService(s2).get(alert.id)
        assert a.status == "investigating"
        kinds = [(u.kind, u.old_status, u.new_status, u.note) for u in a.updates]
        assert kinds == [
            ("status_change", "new", "investigating", None),
            ("note", None, None, "checking firewall"),
        ]


def test_same_status_records_no_change(session, analysis):
    svc = AlertService(session)
    (alert,) = svc.create_from_findings(analysis.id, [finding()])
    session.commit()
    svc.update(alert.id, status="new", note="n")
    assert [u.kind for u in alert.updates] == ["note"]


@pytest.mark.parametrize(
    "kw",
    [{}, {"status": "closed"}, {"note": "   "}, {"note": "x" * 4001}],
)
def test_invalid_updates_rejected(session, analysis, kw):
    svc = AlertService(session)
    (alert,) = svc.create_from_findings(analysis.id, [finding()])
    session.commit()
    with pytest.raises(AlertValidationError):
        svc.update(alert.id, **kw)
    assert alert.status == "new"


def test_missing_alert(session):
    with pytest.raises(AlertNotFoundError):
        AlertService(session).get("nope")


def test_list_filters_sorting_pagination(session, analysis):
    svc = AlertService(session)
    svc.create_from_findings(
        analysis.id,
        [
            finding("a", Severity.LOW, 5.0, title="Alpha scan"),
            finding("b", Severity.HIGH, 9.0, rule="syn_heavy", title="Beta flood"),
            finding("c", Severity.HIGH, 1.0, title="Gamma"),
        ],
    )
    session.commit()
    allp = svc.list()
    assert [a.title for a in allp.items] == ["Gamma", "Beta flood", "Alpha scan"]
    assert svc.list(severity="high").total == 2
    assert svc.list(rule_id="syn_heavy").total == 1
    assert [a.title for a in svc.list(q="alpha").items] == ["Alpha scan"]
    assert svc.list(q="%").total == 0  # wildcard is escaped
    p2 = svc.list(page=2, page_size=2)
    assert len(p2.items) == 1 and p2.total == 3
    assert svc.list(page_size=10_000).page_size == 200


def test_counts_by_severity(session, analysis):
    svc = AlertService(session)
    svc.create_from_findings(analysis.id, [finding("a", Severity.LOW), finding("b", Severity.LOW)])
    session.commit()
    c = svc.counts_by_severity()
    assert c["low"] == 2 and c["critical"] == 0 and list(c)[0] == "informational"


def test_cascade_delete(session, analysis):
    svc = AlertService(session)
    (alert,) = svc.create_from_findings(analysis.id, [finding()])
    session.commit()
    svc.update(alert.id, note="hello")
    session.delete(analysis)
    session.commit()
    assert session.scalars(select(Alert)).all() == []
    assert session.scalars(select(AlertUpdate)).all() == []


def test_foreign_keys_enforced(session):
    with pytest.raises(Exception):  # noqa: B017
        session.execute(
            text("INSERT INTO alert_updates (alert_id, kind, created_at) VALUES ('x','note',NULL)")
        )
        session.commit()


def test_schema_version_recorded_and_idempotent(engine):
    init_db(engine)
    init_db(engine)
    with engine.connect() as c:
        v = c.execute(text("SELECT value FROM app_settings WHERE key='schema_version'")).scalar()
    assert str(SCHEMA_VERSION) in str(v)


def test_rule_metadata_sync(session):
    sync_rule_metadata(session)
    sync_rule_metadata(session)
    rows = session.scalars(select(RuleMetadata)).all()
    assert {r.rule_id for r in rows} >= {"port_scan", "dns_anomaly", "traffic_spike"}
    assert all(r.limitations for r in rows)


def test_settings_defaults_and_roundtrip(session):
    svc = SettingsService(session)
    assert svc.get().max_upload_mb == 50
    payload = svc.get().model_dump()
    payload["detection"] = {"port_scan": {"enabled": True, "params": {"min_ports": 10}}}
    payload["retention_hours"] = 48
    svc.update(payload)
    got = SettingsService(session).get()
    assert got.retention_hours == 48 and got.detection["port_scan"].params["min_ports"] == 10
    assert svc.detection_config()["port_scan"]["params"] == {"min_ports": 10}


@pytest.mark.parametrize(
    "patch",
    [
        {"max_upload_mb": 0},
        {"max_upload_mb": 9999},
        {"retention_hours": -1},
        {"unknown_field": 1},
        {"ui": {"density": "huge"}},
        {"detection": {"nope": {"enabled": True}}},
        {"detection": {"port_scan": {"params": {"min_ports": 1}}}},
        {"detection": {"port_scan": {"params": {"bogus": 1}}}},
    ],
)
def test_settings_validation(session, patch):
    svc = SettingsService(session)
    payload = {**svc.get().model_dump(), **patch}
    with pytest.raises(SettingsValidationError):
        svc.update(payload)
    assert svc.get().max_upload_mb == 50
