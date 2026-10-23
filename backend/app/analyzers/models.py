"""Normalized packet metadata. Payloads are never stored."""

from dataclasses import dataclass, field

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(frozen=True, slots=True)
class PacketMeta:
    ts: float | None
    src: str
    dst: str
    proto: str  # TCP | UDP | ICMP | OTHER
    length: int
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    dns_qname: str | None = None
    dns_qtype: int | None = None
    dns_is_response: bool = False
    dns_rcode: int | None = None


@dataclass(slots=True)
class ParseStats:
    packets_read: int = 0
    packets_parsed: int = 0
    skipped_non_ip: int = 0
    malformed: int = 0
    missing_timestamp: int = 0
    capture_truncated: bool = False  # file ends mid-record
    stopped_by_packet_limit: bool = False
    stopped_by_timeout: bool = False
    notes: list[str] = field(default_factory=list)
