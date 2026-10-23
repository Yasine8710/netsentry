"""Bidirectional flow tracking with TCP handshake evidence (bounded flow table)."""

from dataclasses import dataclass

from app.analyzers.models import ACK, FIN, RST, SYN, PacketMeta

Endpoint = tuple[str, int | None]

# Flow outcome labels. They describe what the capture shows, not what really happened.
STATE_ESTABLISHED = "handshake_observed"
STATE_NO_RESPONSE = "no_response_observed"
STATE_REFUSED = "reset_by_responder"
STATE_PARTIAL = "partial_or_midstream"
STATE_NON_TCP = "non_tcp"


@dataclass(slots=True)
class Flow:
    proto: str
    client: Endpoint
    server: Endpoint
    first_ts: float | None
    last_ts: float | None
    pkts_c: int = 0
    pkts_s: int = 0
    bytes_c: int = 0
    bytes_s: int = 0
    syn: int = 0  # SYN (no ACK) from client, retransmissions included
    synack: int = 0  # SYN+ACK from server
    ack_c: int = 0  # ACK-only-or-data packets from client after a SYN+ACK
    rst_c: int = 0
    rst_s: int = 0
    fin: int = 0

    @property
    def packets(self) -> int:
        return self.pkts_c + self.pkts_s

    @property
    def bytes(self) -> int:
        return self.bytes_c + self.bytes_s

    @property
    def state(self) -> str:
        if self.proto != "TCP":
            return STATE_NON_TCP
        if self.syn and self.synack and self.ack_c:
            return STATE_ESTABLISHED
        if self.syn and self.pkts_s == 0:
            return STATE_NO_RESPONSE
        if self.syn and self.rst_s and not self.synack:
            return STATE_REFUSED
        return STATE_PARTIAL


class FlowAnalyzer:
    def __init__(self, max_flows: int = 200_000) -> None:
        self.max_flows = max_flows
        self._flows: dict[tuple, Flow] = {}
        self.flows_dropped = 0

    @staticmethod
    def _key(proto: str, a: Endpoint, b: Endpoint) -> tuple:
        lo, hi = sorted((a, b), key=lambda e: (e[0], -1 if e[1] is None else e[1]))
        return proto, lo, hi

    def add(self, p: PacketMeta) -> None:
        if p.proto == "OTHER":
            return
        src: Endpoint = (p.src, p.sport)
        dst: Endpoint = (p.dst, p.dport)
        key = self._key(p.proto, src, dst)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self.max_flows:
                self.flows_dropped += 1
                return
            flags = p.tcp_flags or 0
            # A lone SYN/ACK means we joined mid-handshake: the sender is the server.
            server_first = p.proto == "TCP" and flags & SYN and flags & ACK
            client, server = (dst, src) if server_first else (src, dst)
            flow = Flow(p.proto, client, server, p.ts, p.ts)
            self._flows[key] = flow
        self._update(flow, p, src)

    @staticmethod
    def _update(f: Flow, p: PacketMeta, src: Endpoint) -> None:
        if p.ts is not None:
            if f.first_ts is None or p.ts < f.first_ts:
                f.first_ts = p.ts
            if f.last_ts is None or p.ts > f.last_ts:
                f.last_ts = p.ts
        from_client = src == f.client
        if from_client:
            f.pkts_c += 1
            f.bytes_c += p.length
        else:
            f.pkts_s += 1
            f.bytes_s += p.length
        if p.proto != "TCP":
            return
        fl = p.tcp_flags or 0
        if fl & SYN and not fl & ACK and from_client:
            f.syn += 1
        elif fl & SYN and fl & ACK and not from_client:
            f.synack += 1
        elif fl & ACK and from_client and f.synack:
            f.ack_c += 1
        if fl & RST:
            if from_client:
                f.rst_c += 1
            else:
                f.rst_s += 1
        if fl & FIN:
            f.fin += 1

    def iter_flows(self) -> list[Flow]:
        """Deterministic order: by first timestamp, then endpoints."""
        return sorted(
            self._flows.values(),
            key=lambda f: (
                f.first_ts if f.first_ts is not None else float("inf"),
                f.proto,
                f.client[0],
                f.client[1] or 0,
                f.server[0],
                f.server[1] or 0,
            ),
        )

    def __len__(self) -> int:
        return len(self._flows)
