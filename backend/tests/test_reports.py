import csv
import io
import json

from app.reports.report_service import csv_safe
from tests.conftest import upload


def test_json_report(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    r = client.get(f"/api/analyses/{aid}/reports/json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    d = json.loads(r.text)
    assert d["capture"]["analysis_id"] == aid and d["statistics"]["packets"] > 0
    assert d["detections"] and d["limitations"] and d["detection_rules"]
    assert d["detections"][0]["recommended_steps"]


def test_reports_contain_no_payload_fields(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    text = client.get(f"/api/analyses/{aid}/reports/json").text.lower()
    assert "payload" not in text.replace("payloads are not", "").replace("no packet payload", "")


def test_csv_report(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    alert = client.get(f"/api/analyses/{aid}/alerts").json()["items"][0]
    client.patch(f"/api/alerts/{alert['id']}", json={"note": "checked, benign scanner"})
    r = client.get(f"/api/analyses/{aid}/reports/csv")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == client.get(f"/api/analyses/{aid}/alerts").json()["total"]
    assert {"alert_id", "rule_id", "severity", "status", "analyst_notes"} <= set(rows[0])
    assert any("checked, benign scanner" in row["analyst_notes"] for row in rows)


def test_csv_formula_injection_neutralized():
    for bad in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx"):
        assert csv_safe(bad).startswith("'")
    assert csv_safe("normal") == "normal" and csv_safe(None) == ""


def test_html_report_escapes_and_has_sections(client, scan_pcap):
    aid = upload(client, scan_pcap).json()["id"]
    alert = client.get(f"/api/analyses/{aid}/alerts").json()["items"][0]
    client.patch(f"/api/alerts/{alert['id']}", json={"note": "<script>alert(1)</script>"})
    r = client.get(f"/api/analyses/{aid}/reports/html")
    assert r.headers["content-type"].startswith("text/html")
    assert "<script" not in r.text.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text
    assert "content-security-policy" in r.headers
    for section in ("Capture", "Detections", "Limitations", "Detection rules used"):
        assert section in r.text


def test_html_filename_xss_escaped(client, env):
    from app.analyzers.synthetic import normal_traffic, write_pcap

    f = write_pcap(env / "x.pcap", normal_traffic(n=3))
    with open(f, "rb") as fh:
        aid = client.post(
            "/api/analyses", files={"file": ('a"><img src=x onerror=1>.pcap', fh)}
        ).json()["id"]
    html = client.get(f"/api/analyses/{aid}/reports/html").text
    assert "<img" not in html


def test_demo_report_is_labelled(client):
    aid = client.post("/api/analyses/demo").json()["id"]
    assert "DEMO DATA" in client.get(f"/api/analyses/{aid}/reports/html").text
    assert json.loads(client.get(f"/api/analyses/{aid}/reports/json").text)["capture"]["is_demo"]


def test_report_missing_analysis_404(client):
    for kind in ("json", "csv", "html"):
        assert client.get(f"/api/analyses/nope/reports/{kind}").status_code == 404
