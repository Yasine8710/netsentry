"""Deterministic synthetic capture generator (tests and sample data). Local files only."""

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def _stamp(pkt, ts: float):
    pkt.time = ts
    return pkt


def tcp(src, dst, sport, dport, flags, ts, size=0):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if size:
        p = p / ("x" * size)
    return _stamp(p, ts)


def udp(src, dst, sport, dport, ts, size=0):
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if size:
        p = p / ("x" * size)
    return _stamp(p, ts)


def icmp(src, dst, ts, icmp_type=8):
    return _stamp(Ether() / IP(src=src, dst=dst) / ICMP(type=icmp_type), ts)


def dns_query(src, dst, qname, ts, sport=40000):
    p = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    return _stamp(p, ts)


def dns_response(src, dst, qname, ts, rcode=0, dport=40000):
    p = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=53, dport=dport)
        / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=qname))
    )
    return _stamp(p, ts)


def port_scan(src, dst, ports, start=1000.0, step=0.01):
    """SYN to many distinct ports with no reply (offensive-free: written to a local file only)."""
    return [
        tcp(src, dst, 50000 + i % 1000, port, "S", start + i * step) for i, port in enumerate(ports)
    ]


def normal_traffic(start=1000.0, n=60):
    pkts = []
    for i in range(n):
        t = start + i * 0.5
        pkts.append(tcp("10.0.0.5", "93.184.216.34", 51000, 443, "S" if i == 0 else "A", t, 100))
        pkts.append(
            tcp("93.184.216.34", "10.0.0.5", 443, 51000, "SA" if i == 0 else "A", t + 0.01, 400)
        )
    pkts.append(dns_query("10.0.0.5", "10.0.0.1", "example.com", start + 1))
    pkts.append(dns_response("10.0.0.1", "10.0.0.5", "example.com", start + 1.02))
    pkts.append(icmp("10.0.0.5", "10.0.0.1", start + 2))
    return pkts


def write_pcap(path: Path, packets) -> Path:
    wrpcap(str(path), list(packets))
    return path
