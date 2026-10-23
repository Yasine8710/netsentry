import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.analyzers.synthetic import normal_traffic, port_scan, write_pcap
from app.core import db as dbmod
from app.core.config import get_settings
from app.main import create_app
from app.models.tables import Analysis, utcnow
from app.services.analysis_service import AnalysisService, UploadError, safe_display_name


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSENTRY_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("NETSENTRY_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    dbmod._engine = None
    dbmod._factory = None
    yield tmp_path
    if dbmod._engine is not None:
        dbmod._engine.dispose()
    dbmod._engine = None
    dbmod._factory = None
    get_settings.cache_clear()


@pytest.fixture
def client(env):
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def scan_pcap(env):
    pk = port_scan("192.0.2.50", "10.0.0.10", range(1, 41)) + normal_traffic()
    return write_pcap(env / "scan.pcap", pk)


def upload(client, path, name=None):
    with open(path, "rb") as fh:
        return client.post("/api/analyses", files={"file": (name or path.name, fh)})


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_openapi_documents_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ("/api/analyses", "/api/analyses/{analysis_id}/traffic", "/api/alerts/{alert_id}"):
        assert p in paths


def test_upload_and_analysis(client, scan_pcap, env):
    r = upload(client, scan_pcap)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "completed" and body["summary"]["packets"] > 100
    assert (
        body["alert_counts"]["low"] + body["alert_counts"]["medium"] + body["alert_counts"]["high"]
        >= 1
    )
    assert body["file_format"] == "pcap"
    assert list((env / "uploads").glob("*")) == []  # temp file cleaned up
    got = client.get(f"/api/analyses/{body['id']}").json()
    assert got["summary"]["data"]["protocols"]
    alerts = client.get(f"/api/analyses/{body['id']}/alerts").json()
    assert alerts["total"] >= 1 and alerts["items"][0]["rule_id"] == "port_scan"


def test_list_analyses_paginates(client, scan_pcap):
    for _ in range(3):
        upload(client, scan_pcap)
    r = client.get("/api/analyses", params={"page": 2, "page_size": 2}).json()
    assert r["total"] == 3 and len(r["items"]) == 1 and r["items"][0]["alert_total"] >= 1


def test_rejects_wrong_extension(client, env):
    f = env / "a.txt"
    f.write_bytes(b"hello")
    assert upload(client, f).status_code == 415


def test_rejects_non_capture_content(client, env):
    f = env / "fake.pcap"
    f.write_bytes(b"this is not a capture at all")
    r = upload(client, f)
    assert r.status_code == 422 and "pcap" in r.json()["detail"].lower()
    assert client.get("/api/analyses").json()["total"] == 0


def test_rejects_empty_file(client, env):
    f = env / "empty.pcap"
    f.write_bytes(b"")
    assert upload(client, f).status_code == 400


def test_rejects_oversized_upload(client, env):
    body = client.get("/api/settings").json()
    client.put("/api/settings", json={**body, "max_upload_mb": 1})
    f = env / "big.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * (3 * 1024 * 1024))
    r = upload(client, f)
    assert r.status_code == 413 and "limit" in r.json()["detail"].lower()
    assert list((env / "uploads").glob("*")) == []


def test_service_enforces_limit_without_content_length(env, client):
    # Streaming check inside the service (defence in depth behind the middleware).
    with dbmod.get_engine().connect() as conn:
        from sqlalchemy.orm import Session

        with Session(conn) as s:
            svc = AnalysisService(s)
            svc.cfg.max_upload_mb = 1
            with pytest.raises(UploadError) as e:
                svc.save_upload(io.BytesIO(b"x" * (2 * 1024 * 1024)), "x.pcap")
            assert e.value.status_code == 413
    assert list((env / "uploads").glob("*")) == []


def test_truncated_capture_is_reported(client, env):
    f = write_pcap(env / "t.pcap", normal_traffic(n=20))
    data = f.read_bytes()
    f.write_bytes(data[:-30])
    r = upload(client, f)
    assert r.status_code == 201
    assert r.json()["parse_stats"]["capture_truncated"] is True
    assert any("truncated" in n.lower() for n in r.json()["notes"])


def test_empty_capture_is_valid(client, env):
    f = write_pcap(env / "e.pcap", [])
    r = upload(client, f)
    assert r.status_code == 201
    assert r.json()["summary"]["packets"] == 0
    assert any("no packets" in n for n in r.json()["notes"])


def test_filename_is_sanitized():
    assert safe_display_name("../../etc/pass<script>.pcap") == "pass" + "script" + ".pcap"
    assert safe_display_name("C:\\evil\\x.pcap") == "x.pcap"
    assert safe_display_name(None) == "capture"


def test_missing_ids_404(client):
    for url in (
        "/api/analyses/nope",
        "/api/analyses/nope/traffic",
        "/api/analyses/nope/alerts",
        "/api/alerts/nope",
    ):
        assert client.get(url).status_code == 404, url
    assert client.delete("/api/analyses/nope").status_code == 404
    assert client.patch("/api/alerts/nope", json={"status": "resolved"}).status_code == 404


def test_traffic_filters_and_pagination(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    r = client.get(f"/api/analyses/{aid}/traffic", params={"page_size": 10}).json()
    assert len(r["items"]) == 10 and r["total"] > 100 and r["truncated"] is False
    dns = client.get(f"/api/analyses/{aid}/traffic", params={"q": "example.com"}).json()
    assert dns["total"] == 2
    tcp443 = client.get(f"/api/analyses/{aid}/traffic", params={"proto": "TCP", "port": 443}).json()
    assert tcp443["total"] > 0 and all(i["proto"] == "TCP" for i in tcp443["items"])
    assert client.get(f"/api/analyses/{aid}/traffic", params={"q": "%"}).json()["total"] == 0
    assert client.get(f"/api/analyses/{aid}/traffic", params={"page_size": 1000}).status_code == 422
    assert client.get(f"/api/analyses/{aid}/traffic", params={"proto": "XYZ"}).status_code == 422


def test_packet_rows_are_capped(client, scan_pcap):
    s = client.get("/api/settings").json()
    client.put("/api/settings", json={**s, "store_packet_rows": 25})
    aid = upload(client, scan_pcap).json()["id"]
    r = client.get(f"/api/analyses/{aid}/traffic").json()
    assert r["truncated"] is True and r["packets_stored"] == 25 and r["total"] == 25


def test_alert_status_and_notes(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    alert = client.get(f"/api/analyses/{aid}/alerts").json()["items"][0]
    detail = client.get(f"/api/alerts/{alert['id']}").json()
    assert detail["status"] == "new" and detail["rule"]["limitations"]
    assert detail["recommended_steps"] and detail["benign_explanations"]

    r = client.patch(
        f"/api/alerts/{alert['id']}", json={"status": "investigating", "note": "on it"}
    )
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "investigating" and [u["kind"] for u in d["updates"]] == [
        "status_change",
        "note",
    ]
    assert client.get("/api/alerts?status=investigating").json()["total"] == 1
    total = client.get("/api/alerts").json()["total"]
    assert client.get("/api/alerts?status=new").json()["total"] == total - 1


@pytest.mark.parametrize(
    "body", [{}, {"status": "closed"}, {"note": "   "}, {"note": "x" * 4001}, {"other": 1}]
)
def test_alert_patch_validation(client, scan_pcap, body):
    aid = upload(client, scan_pcap).json()["id"]
    alert = client.get(f"/api/analyses/{aid}/alerts").json()["items"][0]
    assert client.patch(f"/api/alerts/{alert['id']}", json=body).status_code == 422


def test_settings_apply_to_detection(client, scan_pcap):
    s = client.get("/api/settings").json()
    s["detection"] = {"port_scan": {"enabled": False, "params": {}}}
    assert client.put("/api/settings", json=s).status_code == 200
    aid = upload(client, scan_pcap).json()["id"]
    alerts = client.get(f"/api/analyses/{aid}/alerts").json()["items"]
    assert all(a["rule_id"] != "port_scan" for a in alerts)


@pytest.mark.parametrize(
    "patch",
    [
        {"max_upload_mb": 0},
        {"detection": {"ghost": {"enabled": True, "params": {}}}},
        {"detection": {"port_scan": {"enabled": True, "params": {"min_ports": 0}}}},
        {"retention_hours": 0},
    ],
)
def test_settings_validation_422(client, patch):
    s = client.get("/api/settings").json()
    assert client.put("/api/settings", json={**s, **patch}).status_code == 422


def test_rules_endpoint(client):
    rules = client.get("/api/rules").json()
    assert {r["id"] for r in rules} == {
        "port_scan",
        "repeated_connections",
        "syn_heavy",
        "incomplete_connections",
        "traffic_spike",
        "dns_anomaly",
    }
    assert all(r["limitations"] and r["effective_params"] for r in rules)


def test_overview_empty_then_demo_is_flagged(client, scan_pcap):
    o = client.get("/api/overview").json()
    assert o["has_data"] is False and o["packets"] == 0

    demo = client.post("/api/analyses/demo")
    assert demo.status_code == 201 and demo.json()["is_demo"] is True
    o = client.get("/api/overview").json()
    assert o["has_data"] and o["includes_demo"] and o["demo_analyses"] == 1
    assert o["traffic_over_time"]["is_demo"] is True
    assert sum(o["alerts_by_severity"].values()) >= 3
    assert client.get("/api/overview?include_demo=false").json()["has_data"] is False

    upload(client, scan_pcap)
    mixed = client.get("/api/overview").json()
    assert mixed["analyses"] == 2 and mixed["includes_demo"]
    real = client.get("/api/overview?include_demo=false").json()
    assert real["analyses"] == 1 and real["includes_demo"] is False


def test_demo_triggers_expected_rules(client):
    aid = client.post("/api/analyses/demo").json()["id"]
    rules = {
        a["rule_id"]
        for a in client.get(f"/api/analyses/{aid}/alerts?page_size=200").json()["items"]
    }
    assert {"port_scan", "syn_heavy", "traffic_spike", "dns_anomaly"} <= rules


def test_retention_purge(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    with dbmod._factory() as s:
        a = s.get(Analysis, aid)
        a.created_at = utcnow() - timedelta(hours=1000)
        s.commit()
        assert AnalysisService(s).purge_expired() == 1
    assert client.get(f"/api/analyses/{aid}").status_code == 404
    assert client.get(f"/api/analyses/{aid}/alerts").status_code == 404


def test_delete_analysis_removes_alerts(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    assert client.delete(f"/api/analyses/{aid}").status_code == 204
    assert client.get("/api/alerts").json()["total"] == 0


def test_cors_restricted(client):
    ok = client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    bad = client.options(
        "/api/health",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers
