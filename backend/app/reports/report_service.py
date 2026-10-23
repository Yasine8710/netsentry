"""JSON / CSV / HTML exports. Reports never contain packet payloads."""

import csv
import io
import json
from datetime import UTC, datetime
from html import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detectors.engine import DetectionEngine
from app.models.tables import Alert, Analysis, AnalysisSummary

GENERAL_LIMITATIONS = [
    "Detections are heuristics over packet headers and flow statistics. They are indicators "
    "for investigation, not proof of an attack.",
    "Packet payloads are not stored or analyzed; encrypted traffic contents are not visible.",
    "Whether a connection failed or succeeded is inferred only from captured packets; a capture "
    "taken at one point can miss replies or part of a connection.",
    "Thresholds are configurable; the same traffic can trigger different alerts under different "
    "settings.",
    "Confidence is an evidence-strength indicator relative to the configured thresholds, not the "
    "probability of malicious activity.",
]

CSV_COLUMNS = [
    "alert_id",
    "analysis_id",
    "rule_id",
    "severity",
    "confidence",
    "confidence_label",
    "status",
    "title",
    "first_seen_utc",
    "last_seen_utc",
    "src_ips",
    "dst_ips",
    "explanation",
    "why_suspicious",
    "benign_explanations",
    "recommended_steps",
    "analyst_notes",
]


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection (cells starting with = + - @ tab or CR)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


class ReportService:
    def __init__(self, session: Session) -> None:
        self.s = session

    def _alerts(self, analysis_id: str) -> list[Alert]:
        return list(
            self.s.scalars(
                select(Alert)
                .where(Alert.analysis_id == analysis_id)
                .order_by(Alert.severity_rank.desc(), Alert.first_seen, Alert.id)
            )
        )

    def build(self, analysis: Analysis) -> dict:
        summary = self.s.get(AnalysisSummary, analysis.id)
        alerts = self._alerts(analysis.id)
        rules = DetectionEngine(config=analysis.detection_config or {}).rules_metadata()
        return {
            "report_version": 1,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "capture": {
                "analysis_id": analysis.id,
                "filename": analysis.filename,
                "format": analysis.file_format,
                "file_size_bytes": analysis.file_size,
                "status": analysis.status,
                "is_demo": analysis.is_demo,
                "analyzed_at": analysis.created_at.isoformat() + "Z",
                "parse_stats": analysis.parse_stats,
                "notes": analysis.notes or [],
            },
            "statistics": summary.data if summary else None,
            "detections": [self._alert_dict(a) for a in alerts],
            "detection_rules": rules,
            "limitations": GENERAL_LIMITATIONS,
        }

    @staticmethod
    def _alert_dict(a: Alert) -> dict:
        return {
            "id": a.id,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "confidence": a.confidence,
            "confidence_label": a.confidence_label,
            "status": a.status,
            "title": a.title,
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "first_seen_utc": _iso(a.first_seen),
            "last_seen_utc": _iso(a.last_seen),
            "src_ips": a.src_ips,
            "dst_ips": a.dst_ips,
            "evidence": a.evidence,
            "explanation": a.explanation,
            "why_suspicious": a.why_suspicious,
            "benign_explanations": a.benign_explanations,
            "recommended_steps": a.recommended_steps,
            "analyst_notes": [
                {"at": u.created_at.isoformat() + "Z", "note": u.note}
                for u in a.updates
                if u.kind == "note"
            ],
        }

    def to_json(self, analysis: Analysis) -> str:
        return json.dumps(self.build(analysis), indent=2, sort_keys=False, default=str)

    def to_csv(self, analysis: Analysis) -> str:
        out = io.StringIO()
        w = csv.writer(out, lineterminator="\r\n")
        w.writerow(CSV_COLUMNS)
        for a in self._alerts(analysis.id):
            d = self._alert_dict(a)
            w.writerow(
                [
                    csv_safe(v)
                    for v in (
                        d["id"],
                        analysis.id,
                        d["rule_id"],
                        d["severity"],
                        d["confidence"],
                        d["confidence_label"],
                        d["status"],
                        d["title"],
                        d["first_seen_utc"],
                        d["last_seen_utc"],
                        "; ".join(d["src_ips"]),
                        "; ".join(d["dst_ips"]),
                        d["explanation"],
                        d["why_suspicious"],
                        " | ".join(d["benign_explanations"]),
                        " | ".join(d["recommended_steps"]),
                        " | ".join(n["note"] for n in d["analyst_notes"]),
                    )
                ]
            )
        return out.getvalue()

    def to_html(self, analysis: Analysis) -> str:
        r = self.build(analysis)
        e = escape
        cap = r["capture"]
        st = r["statistics"] or {}

        def li(items) -> str:
            return "".join(f"<li>{e(str(i))}</li>" for i in items)

        def fmt_bytes(n) -> str:
            return f"{n:,}" if isinstance(n, int) else "-"

        demo = (
            '<p class="demo">DEMO DATA: this report was generated from a built-in synthetic '
            "capture, not real network traffic.</p>"
            if cap["is_demo"]
            else ""
        )
        proto_rows = "".join(
            f"<tr><td>{e(p['protocol'])}</td><td>{p['packets']:,}</td><td>{p['bytes']:,}</td></tr>"
            for p in st.get("protocols", [])
        )
        top_rows = "".join(
            f"<tr><td>{e(p['ip'])}</td><td>{p['packets']:,}</td><td>{p['bytes']:,}</td></tr>"
            for p in st.get("top_sources", [])[:10]
        )
        alerts_html = ""
        for d in r["detections"]:
            ev = "".join(
                f"<tr><th>{e(str(k))}</th><td>{e(json.dumps(v) if not isinstance(v, str) else v)}</td></tr>"
                for k, v in d["evidence"].items()
            )
            notes = li(n["note"] for n in d["analyst_notes"]) or "<li>None</li>"
            alerts_html += f"""
<section class="alert sev-{e(d["severity"])}">
  <h3>{e(d["title"])}</h3>
  <p class="meta"><span class="badge">{e(d["severity"])}</span>
    rule <code>{e(d["rule_id"])}</code> &middot; status {e(d["status"])} &middot;
    evidence strength {e(d["confidence_label"])} ({d["confidence"]})</p>
  <p class="meta">First seen {e(d["first_seen_utc"] or "n/a")} &middot; last seen {e(d["last_seen_utc"] or "n/a")}
    &middot; sources {e(", ".join(d["src_ips"]) or "n/a")} &middot; destinations {e(", ".join(d["dst_ips"][:10]) or "n/a")}</p>
  <p>{e(d["explanation"])}</p>
  <h4>Why it may be suspicious</h4><p>{e(d["why_suspicious"])}</p>
  <h4>Possible benign explanations</h4><ul>{li(d["benign_explanations"])}</ul>
  <h4>Recommended investigation steps</h4><ul>{li(d["recommended_steps"])}</ul>
  <h4>Supporting evidence</h4><table>{ev}</table>
  <h4>Analyst notes</h4><ul>{notes}</ul>
</section>"""
        rules_html = "".join(
            f"<li><strong>{e(x['name'])}</strong> (<code>{e(x['id'])}</code>): {e(x['description'])}"
            f"<ul>{li(x['limitations'])}</ul></li>"
            for x in r["detection_rules"]
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetSentry report - {e(cap["filename"])}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#0f172a}}
h1{{margin-bottom:0}} h2{{border-bottom:1px solid #cbd5e1;padding-bottom:.25rem;margin-top:2rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0}} th,td{{border:1px solid #cbd5e1;padding:.3rem .5rem;text-align:left;vertical-align:top}}
code{{background:#f1f5f9;padding:0 .25rem}} .meta{{color:#475569;font-size:.9rem}}
.alert{{border:1px solid #cbd5e1;border-left-width:6px;padding:.5rem 1rem;margin:1rem 0;border-radius:4px}}
.sev-critical,.sev-high{{border-left-color:#dc2626}} .sev-medium{{border-left-color:#f59e0b}}
.sev-low{{border-left-color:#0ea5e9}} .sev-informational{{border-left-color:#64748b}}
.badge{{background:#0f172a;color:#fff;padding:0 .4rem;border-radius:3px;text-transform:uppercase;font-size:.75rem}}
.demo{{background:#fef3c7;border:1px solid #f59e0b;padding:.5rem;font-weight:600}}
</style></head><body>
<h1>NetSentry analysis report</h1>
<p class="meta">Generated {e(r["generated_at"])}</p>
{demo}
<h2>Capture</h2>
<table>
<tr><th>File</th><td>{e(cap["filename"])}</td></tr>
<tr><th>Analysis ID</th><td><code>{e(cap["analysis_id"])}</code></td></tr>
<tr><th>Format / size</th><td>{e(str(cap["format"]))} / {fmt_bytes(cap["file_size_bytes"])} bytes</td></tr>
<tr><th>Analyzed at</th><td>{e(cap["analyzed_at"])}</td></tr>
<tr><th>Packets / bytes</th><td>{st.get("packets", 0):,} / {st.get("bytes", 0):,}</td></tr>
<tr><th>Duration</th><td>{e("n/a" if st.get("duration_s") is None else f"{st['duration_s']:.2f} s")}</td></tr>
<tr><th>Capture start / end (UTC)</th><td>{e(_iso(st.get("first_ts")) or "n/a")} / {e(_iso(st.get("last_ts")) or "n/a")}</td></tr>
<tr><th>Unique source / destination IPs</th><td>{st.get("unique_src_ips", 0):,} / {st.get("unique_dst_ips", 0):,}</td></tr>
</table>
<h3>Processing notes</h3><ul>{li(cap["notes"]) or "<li>None</li>"}</ul>
<h2>Protocols</h2>
<table><tr><th>Protocol</th><th>Packets</th><th>Bytes</th></tr>{proto_rows}</table>
<h2>Top sources</h2>
<table><tr><th>IP</th><th>Packets</th><th>Bytes</th></tr>{top_rows}</table>
<h2>Detections ({len(r["detections"])})</h2>
{alerts_html or "<p>No detections.</p>"}
<h2>Detection rules used</h2><ul>{rules_html}</ul>
<h2>Limitations</h2><ul>{li(r["limitations"])}</ul>
<p class="meta">This report contains metadata only. Packet payloads are not stored or exported.</p>
</body></html>"""
