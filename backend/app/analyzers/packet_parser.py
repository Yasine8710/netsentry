"""Streaming PCAP/PCAPNG parser producing normalized PacketMeta records."""

import logging
import time
from collections.abc import Iterator
from pathlib import Path
from struct import error as struct_error

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from app.analyzers.models import PacketMeta, ParseStats

PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
MAX_QNAME = 253


class InvalidCaptureError(ValueError):
    """The file is not a readable PCAP/PCAPNG capture."""


def detect_format(path: Path) -> str:
    """Return 'pcap' or 'pcapng' from magic bytes; raise InvalidCaptureError otherwise."""
    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise InvalidCaptureError("File is not a PCAP or PCAPNG capture (bad magic bytes).")


class _TruncationWatcher(logging.Handler):
    """Scapy only logs (does not raise) when the last record is cut short."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.hit = False

    def emit(self, record: logging.LogRecord) -> None:
        if "truncated" in record.getMessage().lower():
            self.hit = True


class PacketParser:
    """Parses a capture lazily; memory use does not grow with capture size."""

    def __init__(self, max_packets: int = 500_000, timeout_s: float | None = None) -> None:
        self.max_packets = max_packets
        self.timeout_s = timeout_s
        self.stats = ParseStats()

    def parse(self, path: Path) -> Iterator[PacketMeta]:
        detect_format(path)
        deadline = None if self.timeout_s is None else time.monotonic() + self.timeout_s
        try:
            reader = PcapReader(str(path))
        except (Scapy_Exception, OSError, EOFError, struct_error) as exc:
            raise InvalidCaptureError(f"Cannot read capture: {exc}") from exc
        watcher = _TruncationWatcher()
        scapy_log = logging.getLogger("scapy.runtime")
        scapy_log.addHandler(watcher)
        try:
            while True:
                if self.stats.packets_read >= self.max_packets:
                    self.stats.stopped_by_packet_limit = True
                    self.stats.notes.append(f"Stopped at packet limit ({self.max_packets}).")
                    break
                if deadline is not None and time.monotonic() > deadline:
                    self.stats.stopped_by_timeout = True
                    self.stats.notes.append("Stopped: analysis time limit reached.")
                    break
                try:
                    pkt = next(reader)
                except StopIteration:
                    break
                except (Scapy_Exception, EOFError, struct_error, ValueError) as exc:
                    # Truncated or corrupt record: keep what we already have.
                    self.stats.capture_truncated = True
                    self.stats.notes.append(f"Capture ended abnormally: {exc}")
                    break
                self.stats.packets_read += 1
                try:
                    meta = self._normalize(pkt)
                except Exception:  # noqa: BLE001 - one bad packet must not kill the run
                    self.stats.malformed += 1
                    continue
                if meta is None:
                    self.stats.skipped_non_ip += 1
                    continue
                self.stats.packets_parsed += 1
                yield meta
        finally:
            reader.close()
            scapy_log.removeHandler(watcher)
            if watcher.hit and not self.stats.capture_truncated:
                self.stats.capture_truncated = True
                self.stats.notes.append("Capture file is truncated; last record is incomplete.")
        if self.stats.packets_read == 0 and self.stats.capture_truncated:
            raise InvalidCaptureError("Capture is truncated or corrupt and contains no packets.")

    def _normalize(self, pkt) -> PacketMeta | None:
        if pkt.haslayer(IP):
            ip = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
        else:
            return None

        raw_ts = getattr(pkt, "time", None)
        ts = float(raw_ts) if raw_ts is not None and float(raw_ts) > 0 else None
        if ts is None:
            self.stats.missing_timestamp += 1
        length = int(getattr(pkt, "wirelen", None) or len(pkt))
        src, dst = str(ip.src), str(ip.dst)

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            return PacketMeta(ts, src, dst, "TCP", length, int(t.sport), int(t.dport), int(t.flags))
        if pkt.haslayer(UDP):
            u = pkt[UDP]
            extra = self._dns(pkt)
            return PacketMeta(ts, src, dst, "UDP", length, int(u.sport), int(u.dport), **extra)
        if pkt.haslayer(ICMP):
            return PacketMeta(ts, src, dst, "ICMP", length, icmp_type=int(pkt[ICMP].type))
        return PacketMeta(ts, src, dst, "OTHER", length)

    @staticmethod
    def _dns(pkt) -> dict:
        if not pkt.haslayer(DNS):
            return {}
        d = pkt[DNS]
        out: dict = {"dns_is_response": bool(d.qr), "dns_rcode": int(d.rcode)}
        if d.qd is not None and getattr(d.qd, "qname", None) is not None:
            qname = d.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("ascii", errors="replace")
            out["dns_qname"] = str(qname).rstrip(".").lower()[:MAX_QNAME]
            out["dns_qtype"] = int(d.qd.qtype)
        return out
