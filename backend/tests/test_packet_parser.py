import pytest
from scapy.layers.l2 import ARP, Ether

from app.analyzers.packet_parser import InvalidCaptureError, PacketParser, detect_format
from app.analyzers.synthetic import (
    dns_query,
    dns_response,
    icmp,
    normal_traffic,
    tcp,
    udp,
    write_pcap,
)


def parse(path, **kw):
    p = PacketParser(**kw)
    return list(p.parse(path)), p.stats


def test_empty_capture(tmp_path):
    f = write_pcap(tmp_path / "e.pcap", [])
    pkts, st = parse(f)
    assert pkts == [] and st.packets_read == 0


def test_protocols(tmp_path):
    f = write_pcap(
        tmp_path / "a.pcap",
        [
            tcp("1.1.1.1", "2.2.2.2", 1234, 80, "S", 10.0, 50),
            udp("1.1.1.1", "2.2.2.2", 5000, 6000, 11.0),
            icmp("1.1.1.1", "2.2.2.2", 12.0),
        ],
    )
    pkts, st = parse(f)
    assert [p.proto for p in pkts] == ["TCP", "UDP", "ICMP"]
    assert pkts[0].tcp_flags == 0x02 and pkts[0].dport == 80
    assert pkts[2].icmp_type == 8
    assert st.packets_parsed == 3


def test_dns(tmp_path):
    f = write_pcap(
        tmp_path / "d.pcap",
        [
            dns_query("10.0.0.5", "10.0.0.1", "Example.COM", 10.0),
            dns_response("10.0.0.1", "10.0.0.5", "example.com", 10.1, rcode=3),
        ],
    )
    pkts, _ = parse(f)
    assert pkts[0].dns_qname == "example.com" and not pkts[0].dns_is_response
    assert pkts[1].dns_is_response and pkts[1].dns_rcode == 3


def test_non_ip_skipped(tmp_path):
    f = write_pcap(tmp_path / "arp.pcap", [Ether() / ARP()])
    pkts, st = parse(f)
    assert pkts == [] and st.skipped_non_ip == 1


def test_missing_timestamp(tmp_path):
    p = tcp("1.1.1.1", "2.2.2.2", 1, 2, "S", 0.0)
    f = write_pcap(tmp_path / "t.pcap", [p])
    pkts, st = parse(f)
    assert pkts[0].ts is None and st.missing_timestamp == 1


def test_not_a_capture(tmp_path):
    f = tmp_path / "x.pcap"
    f.write_bytes(b"this is not a pcap file")
    with pytest.raises(InvalidCaptureError):
        parse(f)


def test_truncated_capture_keeps_partial(tmp_path):
    f = write_pcap(tmp_path / "full.pcap", normal_traffic(n=20))
    data = f.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(data[: len(data) - 30])
    pkts, st = parse(cut)
    assert 0 < len(pkts) < 43
    assert st.capture_truncated


def test_truncated_header_only(tmp_path):
    f = tmp_path / "h.pcap"
    f.write_bytes(bytes.fromhex("d4c3b2a1020004"))
    with pytest.raises(InvalidCaptureError):
        parse(f)


def test_packet_limit(tmp_path):
    f = write_pcap(tmp_path / "n.pcap", normal_traffic(n=50))
    pkts, st = parse(f, max_packets=10)
    assert len(pkts) == 10 and st.stopped_by_packet_limit


def test_timeout(tmp_path):
    f = write_pcap(tmp_path / "n.pcap", normal_traffic(n=50))
    pkts, st = parse(f, timeout_s=-1)
    assert pkts == [] and st.stopped_by_timeout


def test_detect_format(tmp_path):
    f = write_pcap(tmp_path / "n.pcap", normal_traffic(n=2))
    assert detect_format(f) == "pcap"


def test_large_input_streams(tmp_path):
    pkts = [
        tcp("10.0.0.1", "10.0.0.2", 1000 + i % 50, 80, "A", 1000 + i * 0.001) for i in range(20000)
    ]
    f = write_pcap(tmp_path / "big.pcap", pkts)
    n = sum(1 for _ in PacketParser().parse(f))
    assert n == 20000


def test_pcapng(tmp_path):
    from scapy.utils import PcapNgWriter

    f = tmp_path / "n.pcapng"
    w = PcapNgWriter(str(f))
    for p in normal_traffic(n=3):
        w.write(p)
    w.close()
    assert detect_format(f) == "pcapng"
    pkts, st = parse(f)
    assert st.packets_parsed == len(pkts) == 9
