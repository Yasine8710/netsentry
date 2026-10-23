"""Streaming traffic statistics with bounded memory."""

from collections import Counter
from dataclasses import dataclass, field

from app.analyzers.models import ACK, FIN, RST, SYN, PacketMeta
from app.analyzers.timeseries import TimeSeries

TOP_N = 20


class BoundedCounter:
    """Counter that stops admitting new keys at `cap` (existing keys keep counting)."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.c: Counter = Counter()
        self.overflow = 0

    def add(self, key, n: int = 1) -> None:
        if key in self.c or len(self.c) < self.cap:
            self.c[key] += n
        else:
            self.overflow += n

    def top(self, n: int = TOP_N) -> list[tuple]:
        # ties broken by key for deterministic output
        return sorted(self.c.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]

    @property
    def capped(self) -> bool:
        return self.overflow > 0


@dataclass(slots=True)
class DnsSourceStats:
    queries: int = 0
    responses_to: int = 0  # responses received by this host
    nxdomain: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    qnames: set = field(default_factory=set)
    qname_cap_hit: bool = False
    longest_label: int = 0
    total_qname_len: int = 0


class TrafficAggregator:
    def __init__(self, max_tracked: int = 100_000, bucket_s: float = 1.0) -> None:
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.proto_packets: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.src_ips = BoundedCounter(max_tracked)
        self.dst_ips = BoundedCounter(max_tracked)
        self.src_bytes = BoundedCounter(max_tracked)
        self.dst_bytes = BoundedCounter(max_tracked)
        self.src_ports = BoundedCounter(max_tracked)
        self.dst_ports = BoundedCounter(max_tracked)
        self.tcp_flags: Counter = Counter()
        self.icmp_types: Counter = Counter()
        self.series = TimeSeries(bucket_s=bucket_s)
        self.dns_packets = 0
        self.dns_queries = 0
        self.dns_responses = 0
        self.dns_nxdomain = 0
        self.dns_qnames = BoundedCounter(max_tracked)
        self.dns_by_source: dict[str, DnsSourceStats] = {}
        self._max_tracked = max_tracked
        self._qname_cap = 5000

    def add(self, p: PacketMeta) -> None:
        self.packets += 1
        self.bytes += p.length
        self.proto_packets[p.proto] += 1
        self.proto_bytes[p.proto] += p.length
        self.src_ips.add(p.src)
        self.dst_ips.add(p.dst)
        self.src_bytes.add(p.src, p.length)
        self.dst_bytes.add(p.dst, p.length)
        if p.ts is not None:
            self.first_ts = p.ts if self.first_ts is None else min(self.first_ts, p.ts)
            self.last_ts = p.ts if self.last_ts is None else max(self.last_ts, p.ts)
            self.series.add(p.ts, p.length)
        if p.sport is not None:
            self.src_ports.add((p.proto, p.sport))
        if p.dport is not None:
            self.dst_ports.add((p.proto, p.dport))
        if p.proto == "TCP" and p.tcp_flags is not None:
            fl = p.tcp_flags
            if fl & SYN and not fl & ACK:
                self.tcp_flags["SYN"] += 1
            elif fl & SYN and fl & ACK:
                self.tcp_flags["SYN-ACK"] += 1
            if fl & RST:
                self.tcp_flags["RST"] += 1
            if fl & FIN:
                self.tcp_flags["FIN"] += 1
        elif p.proto == "ICMP" and p.icmp_type is not None:
            self.icmp_types[p.icmp_type] += 1
        if p.dns_is_response or p.dns_qname is not None:
            self._add_dns(p)

    def _add_dns(self, p: PacketMeta) -> None:
        self.dns_packets += 1
        if p.dns_is_response:
            self.dns_responses += 1
            if p.dns_rcode == 3:
                self.dns_nxdomain += 1
                self._dns_source(p.dst).nxdomain += 1
            self._dns_source(p.dst).responses_to += 1
            return
        self.dns_queries += 1
        s = self._dns_source(p.src)
        s.queries += 1
        if p.ts is not None:
            s.first_ts = p.ts if s.first_ts is None else min(s.first_ts, p.ts)
            s.last_ts = p.ts if s.last_ts is None else max(s.last_ts, p.ts)
        if p.dns_qname:
            self.dns_qnames.add(p.dns_qname)
            if len(s.qnames) < self._qname_cap:
                s.qnames.add(p.dns_qname)
            else:
                s.qname_cap_hit = True
            s.total_qname_len += len(p.dns_qname)
            s.longest_label = max(s.longest_label, max(map(len, p.dns_qname.split(".")), default=0))

    def _dns_source(self, ip: str) -> DnsSourceStats:
        s = self.dns_by_source.get(ip)
        if s is None:
            if len(self.dns_by_source) >= self._max_tracked:
                return DnsSourceStats()  # throwaway: bounded memory
            s = self.dns_by_source[ip] = DnsSourceStats()
        return s

    @property
    def duration(self) -> float | None:
        if self.first_ts is None or self.last_ts is None:
            return None
        return self.last_ts - self.first_ts

    def summary(self) -> dict:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration_s": self.duration,
            "unique_src_ips": len(self.src_ips.c),
            "unique_dst_ips": len(self.dst_ips.c),
            "unique_ips_capped": self.src_ips.capped or self.dst_ips.capped,
            "protocols": [
                {"protocol": k, "packets": self.proto_packets[k], "bytes": self.proto_bytes[k]}
                for k in sorted(self.proto_packets, key=lambda k: (-self.proto_packets[k], k))
            ],
            "top_sources": [
                {"ip": ip, "packets": n, "bytes": self.src_bytes.c[ip]}
                for ip, n in self.src_ips.top()
            ],
            "top_destinations": [
                {"ip": ip, "packets": n, "bytes": self.dst_bytes.c[ip]}
                for ip, n in self.dst_ips.top()
            ],
            "top_src_ports": [
                {"protocol": k[0], "port": k[1], "packets": n} for k, n in self.src_ports.top()
            ],
            "top_dst_ports": [
                {"protocol": k[0], "port": k[1], "packets": n} for k, n in self.dst_ports.top()
            ],
            "tcp": dict(sorted(self.tcp_flags.items())),
            "udp": {"packets": self.proto_packets.get("UDP", 0)},
            "icmp": {str(k): v for k, v in sorted(self.icmp_types.items())},
            "dns": {
                "packets": self.dns_packets,
                "queries": self.dns_queries,
                "responses": self.dns_responses,
                "nxdomain": self.dns_nxdomain,
                "top_queried": [{"name": n, "count": c} for n, c in self.dns_qnames.top(10)],
            },
            "time_series": {"bucket_s": self.series.bucket_s, "points": self.series.points()},
        }
