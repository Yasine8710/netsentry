"""Upload -> parse -> aggregate -> detect -> persist."""

import re
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.analyzers.packet_parser import InvalidCaptureError, PacketParser, detect_format
from app.analyzers.pipeline import build_context
from app.core.config import get_settings
from app.detectors.engine import DetectionEngine
from app.models.tables import (
    Alert,
    Analysis,
    AnalysisSummary,
    PacketRecord,
    TrafficStat,
    utcnow,
)
from app.services.alert_service import AlertService
from app.services.settings_service import SettingsService, sync_rule_metadata

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
CHUNK = 1024 * 1024
ORPHAN_AGE_S = 3600
BATCH = 5000


class UploadError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def safe_display_name(name: str | None) -> str:
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[\x00-\x1f\x7f<>\"'`]", "", base).strip()
    return (base or "capture")[:120]


class AnalysisService:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.env = get_settings()
        self.cfg = SettingsService(session).get()

    # ---- upload -----------------------------------------------------------
    def save_upload(self, fileobj: BinaryIO, filename: str | None) -> tuple[Path, int, str]:
        """Stream to a generated temp name, enforcing the size limit. Returns (path, size, name)."""
        display = safe_display_name(filename)
        if Path(display).suffix.lower() not in ALLOWED_EXTENSIONS:
            raise UploadError(415, "Unsupported file type. Upload a .pcap, .pcapng or .cap file.")
        limit = self.cfg.max_upload_mb * 1024 * 1024
        self.env.upload_dir.mkdir(parents=True, exist_ok=True)
        path = self.env.upload_dir / f"{uuid.uuid4().hex}.upload"
        size = 0
        try:
            with path.open("wb") as out:
                while chunk := fileobj.read(CHUNK):
                    size += len(chunk)
                    if size > limit:
                        raise UploadError(
                            413, f"File exceeds the {self.cfg.max_upload_mb} MB upload limit."
                        )
                    out.write(chunk)
            if size == 0:
                raise UploadError(400, "The uploaded file is empty.")
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path, size, display

    # ---- analysis ---------------------------------------------------------
    def analyze_file(
        self, path: Path, size: int, display_name: str, is_demo: bool = False
    ) -> Analysis:
        try:
            fmt = detect_format(path)
        except InvalidCaptureError as exc:
            raise UploadError(422, str(exc)) from exc

        detection_config = self.cfg_detection()
        engine = DetectionEngine(config=detection_config)  # validated at save time too
        analysis = Analysis(
            filename=display_name,
            file_format=fmt,
            file_size=size,
            status="running",
            is_demo=is_demo,
            detection_config=detection_config,
        )
        self.s.add(analysis)
        self.s.commit()

        parser = PacketParser(self.cfg.max_packets, self.env.analysis_timeout_s)
        try:
            ctx, agg, flows = build_context(self._stream(parser, path, analysis.id))
            findings = engine.run(ctx)
        except InvalidCaptureError as exc:
            self.s.rollback()  # drop partially inserted packet rows
            self._fail(analysis, str(exc))
            raise UploadError(422, str(exc)) from exc
        except Exception:
            self.s.rollback()
            self._fail(analysis, "Internal error while analyzing the capture.")
            raise

        summary = agg.summary()
        notes = list(ctx.notes) + parser.stats.notes
        if parser.stats.packets_read == 0:
            notes.append("The capture contains no packets.")
        if parser.stats.skipped_non_ip:
            notes.append(f"{parser.stats.skipped_non_ip} non-IP packets (e.g. ARP) were skipped.")
        if parser.stats.missing_timestamp:
            notes.append(f"{parser.stats.missing_timestamp} packets had no usable timestamp.")
        if not ctx.has_reverse_traffic and ctx.flows:
            notes.append(
                "Only one direction of traffic is present; failure/no-response inferences "
                "are unreliable."
            )

        stored = self.s.scalar(
            select(func.count())
            .select_from(PacketRecord)
            .where(PacketRecord.analysis_id == analysis.id)
        )
        self.s.add(
            AnalysisSummary(
                analysis_id=analysis.id,
                packets=summary["packets"],
                bytes=summary["bytes"],
                first_ts=summary["first_ts"],
                last_ts=summary["last_ts"],
                duration_s=summary["duration_s"],
                unique_src_ips=summary["unique_src_ips"],
                unique_dst_ips=summary["unique_dst_ips"],
                data=summary,
            )
        )
        self.s.add_all(self._stat_rows(analysis.id, summary))
        AlertService(self.s).create_from_findings(analysis.id, findings)
        analysis.parse_stats = {
            "packets_read": parser.stats.packets_read,
            "packets_parsed": parser.stats.packets_parsed,
            "skipped_non_ip": parser.stats.skipped_non_ip,
            "malformed": parser.stats.malformed,
            "missing_timestamp": parser.stats.missing_timestamp,
            "capture_truncated": parser.stats.capture_truncated,
            "stopped_by_packet_limit": parser.stats.stopped_by_packet_limit,
            "stopped_by_timeout": parser.stats.stopped_by_timeout,
            "packets_stored": stored,
            "flows": len(flows),
        }
        analysis.notes = notes
        analysis.status = "completed"
        analysis.completed_at = utcnow()
        self.s.commit()
        return analysis

    def cfg_detection(self) -> dict:
        return SettingsService.engine_config(self.cfg)

    def _stream(self, parser: PacketParser, path: Path, analysis_id: str):
        """Yield packets while persisting a capped set of per-packet metadata rows."""
        cap = self.cfg.store_packet_rows
        batch: list[dict] = []
        for seq, p in enumerate(parser.parse(path)):
            if seq < cap:
                info = p.dns_qname
                if p.proto == "TCP" and p.tcp_flags is not None:
                    info = _flag_names(p.tcp_flags)
                elif p.proto == "ICMP" and p.icmp_type is not None:
                    info = f"type {p.icmp_type}"
                batch.append(
                    {
                        "analysis_id": analysis_id,
                        "seq": seq,
                        "ts": p.ts,
                        "src": p.src,
                        "dst": p.dst,
                        "proto": p.proto,
                        "sport": p.sport,
                        "dport": p.dport,
                        "length": p.length,
                        "tcp_flags": p.tcp_flags,
                        "info": info,
                    }
                )
                if len(batch) >= BATCH:
                    self.s.execute(PacketRecord.__table__.insert(), batch)
                    batch.clear()
            yield p
        if batch:
            self.s.execute(PacketRecord.__table__.insert(), batch)

    @staticmethod
    def _stat_rows(analysis_id: str, summary: dict) -> list[TrafficStat]:
        rows = [
            TrafficStat(
                analysis_id=analysis_id,
                kind="protocol",
                key=r["protocol"],
                packets=r["packets"],
                bytes=r["bytes"],
            )
            for r in summary["protocols"]
        ]
        for kind, field in (("src_ip", "top_sources"), ("dst_ip", "top_destinations")):
            rows += [
                TrafficStat(
                    analysis_id=analysis_id,
                    kind=kind,
                    key=r["ip"][:64],
                    packets=r["packets"],
                    bytes=r["bytes"],
                )
                for r in summary[field]
            ]
        return rows

    def _fail(self, analysis: Analysis, message: str) -> None:
        analysis.status = "failed"
        analysis.error = message
        analysis.completed_at = utcnow()
        self.s.commit()

    # ---- full flow --------------------------------------------------------
    def handle_upload(self, fileobj: BinaryIO, filename: str | None) -> Analysis:
        self.purge_expired()
        path, size, display = self.save_upload(fileobj, filename)
        try:
            return self.analyze_file(path, size, display)
        finally:
            path.unlink(missing_ok=True)

    def handle_demo(self) -> Analysis:
        from app.analyzers.synthetic import demo_capture, write_pcap

        self.env.upload_dir.mkdir(parents=True, exist_ok=True)
        path = self.env.upload_dir / f"{uuid.uuid4().hex}.upload"
        try:
            write_pcap(path, demo_capture())
            return self.analyze_file(
                path, path.stat().st_size, "DEMO synthetic capture.pcap", is_demo=True
            )
        finally:
            path.unlink(missing_ok=True)

    # ---- retention --------------------------------------------------------
    def purge_expired(self) -> int:
        cutoff = utcnow() - timedelta(hours=self.cfg.retention_hours)
        ids = list(self.s.scalars(select(Analysis.id).where(Analysis.created_at < cutoff)))
        if ids:
            for table in (PacketRecord, TrafficStat, AnalysisSummary, Alert):
                self.s.execute(delete(table).where(table.analysis_id.in_(ids)))
            self.s.execute(delete(Analysis).where(Analysis.id.in_(ids)))
            self.s.commit()
        self.sweep_orphans()
        return len(ids)

    def sweep_orphans(self) -> None:
        d = self.env.upload_dir
        if not d.is_dir():
            return
        now = time.time()
        for f in d.glob("*.upload"):
            try:
                if now - f.stat().st_mtime > ORPHAN_AGE_S:
                    f.unlink()
            except OSError:
                pass

    def delete(self, analysis_id: str) -> bool:
        a = self.s.get(Analysis, analysis_id)
        if a is None:
            return False
        for table in (PacketRecord, TrafficStat):
            self.s.execute(delete(table).where(table.analysis_id == analysis_id))
        self.s.delete(a)
        self.s.commit()
        return True


def _flag_names(flags: int) -> str:
    names = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
    ]
    return ",".join(n for bit, n in names if flags & bit) or "none"


def init_services(session: Session) -> None:
    sync_rule_metadata(session)
    AnalysisService(session).purge_expired()
