"""Builders for normalized-packet test fixtures (no scapy, fast)."""

from app.analyzers.models import ACK, RST, SYN, PacketMeta
from app.analyzers.pipeline import build_context
from app.detectors.engine import DetectionEngine


def conn(src, dst, sport, dport, ts, outcome="ok"):
    """One TCP connection attempt. outcome: ok | none | rst."""
    pk = [PacketMeta(ts, src, dst, "TCP", 60, sport, dport, SYN)]
    if outcome == "ok":
        pk.append(PacketMeta(ts + 0.001, dst, src, "TCP", 60, dport, sport, SYN | ACK))
        pk.append(PacketMeta(ts + 0.002, src, dst, "TCP", 60, sport, dport, ACK))
    elif outcome == "rst":
        pk.append(PacketMeta(ts + 0.001, dst, src, "TCP", 60, dport, sport, RST | ACK))
    return pk


def flatten(groups):
    return [p for g in groups for p in g]


def normal_packets():
    """A few clients talking to a few servers; every connection completes."""
    out = []
    for i in range(10):
        out += conn("10.0.0.5", "93.184.216.34", 40000 + i, 443, 1000 + i * 30)
        out += conn("10.0.0.6", "10.0.0.10", 41000 + i, 22, 1000 + i * 45)
    return out


def run(packets, config=None, rule_ids=None):
    ctx, _, _ = build_context(packets)
    engine = DetectionEngine(config=config)
    if rule_ids:
        engine.rules = [r for r in engine.rules if r.id in rule_ids]
    return engine.run(ctx), ctx
