from app.analyzers.flow_analyzer import (
    STATE_ESTABLISHED,
    STATE_NO_RESPONSE,
    STATE_PARTIAL,
    STATE_REFUSED,
    FlowAnalyzer,
)
from app.analyzers.models import PacketMeta
from app.analyzers.timeseries import TimeSeries
from app.analyzers.traffic_aggregator import BoundedCounter, TrafficAggregator

S, SA, A, R, F = 0x02, 0x12, 0x10, 0x04, 0x01


def pm(src, dst, proto="TCP", sport=1000, dport=80, flags=None, ts=1.0, length=100, **kw):
    return PacketMeta(ts, src, dst, proto, length, sport, dport, flags, **kw)


def test_totals_and_protocols():
    agg = TrafficAggregator()
    agg.add(pm("a", "b", ts=10.0, length=100))
    agg.add(pm("a", "c", "UDP", ts=12.0, length=50))
    agg.add(pm("b", "a", "ICMP", None, None, ts=14.0, length=20, icmp_type=8))
    s = agg.summary()
    assert (s["packets"], s["bytes"], s["duration_s"]) == (3, 170, 4.0)
    assert s["unique_src_ips"] == 2 and s["unique_dst_ips"] == 3
    assert {p["protocol"] for p in s["protocols"]} == {"TCP", "UDP", "ICMP"}
    assert s["icmp"] == {"8": 1}


def test_no_timestamps():
    agg = TrafficAggregator()
    agg.add(pm("a", "b", ts=None))
    s = agg.summary()
    assert s["packets"] == 1 and s["duration_s"] is None and s["time_series"]["points"] == []


def test_tcp_flag_counts():
    agg = TrafficAggregator()
    for fl in (S, S, SA, A, R, F):
        agg.add(pm("a", "b", flags=fl))
    assert agg.summary()["tcp"] == {"FIN": 1, "RST": 1, "SYN": 2, "SYN-ACK": 1}


def test_dns_summary():
    agg = TrafficAggregator()
    agg.add(pm("a", "r", "UDP", 4000, 53, dns_qname="x.example.com"))
    agg.add(
        pm("r", "a", "UDP", 53, 4000, dns_qname="x.example.com", dns_is_response=True, dns_rcode=3)
    )
    d = agg.summary()["dns"]
    assert (d["queries"], d["responses"], d["nxdomain"]) == (1, 1, 1)
    assert agg.dns_by_source["a"].nxdomain == 1


def test_bounded_counter_caps_keys():
    c = BoundedCounter(2)
    for k in "abcab":
        c.add(k)
    assert set(c.c) == {"a", "b"} and c.overflow == 1 and c.capped


def test_top_is_deterministic():
    c = BoundedCounter(10)
    for k in "zyx":
        c.add(k)
    assert [k for k, _ in c.top()] == ["x", "y", "z"]


def test_timeseries_coarsens_within_cap():
    ts = TimeSeries(bucket_s=1.0, max_buckets=10)
    for i in range(100):
        ts.add(float(i), 10)
    pts = ts.points()
    assert len(pts) <= 10 and ts.bucket_s > 1.0
    assert sum(p["packets"] for p in pts) == 100


def test_dense_counts_include_gaps():
    ts = TimeSeries()
    ts.add(0.0, 1)
    ts.add(3.0, 1)
    assert ts.dense_packet_counts() == [1, 0, 0, 1]


def flows_for(packets, **kw):
    fa = FlowAnalyzer(**kw)
    for p in packets:
        fa.add(p)
    return fa


def test_completed_handshake():
    fa = flows_for(
        [
            pm("c", "s", sport=5000, flags=S, ts=1),
            pm("s", "c", sport=80, dport=5000, flags=SA, ts=2),
            pm("c", "s", sport=5000, flags=A, ts=3),
        ]
    )
    (f,) = fa.iter_flows()
    assert f.state == STATE_ESTABLISHED and f.client == ("c", 5000)


def test_syn_without_reply():
    (f,) = flows_for([pm("c", "s", flags=S)]).iter_flows()
    assert f.state == STATE_NO_RESPONSE


def test_reset_by_responder():
    fa = flows_for(
        [pm("c", "s", sport=5000, flags=S), pm("s", "c", sport=80, dport=5000, flags=R | A)]
    )
    (f,) = fa.iter_flows()
    assert f.state == STATE_REFUSED


def test_midstream_is_partial():
    (f,) = flows_for([pm("c", "s", flags=A)]).iter_flows()
    assert f.state == STATE_PARTIAL


def test_synack_first_makes_sender_the_server():
    (f,) = flows_for([pm("s", "c", sport=80, dport=5000, flags=SA)]).iter_flows()
    assert f.server == ("s", 80)


def test_flow_cap_drops_new_flows_only():
    fa = flows_for([pm("a", "b", sport=i) for i in range(5)], max_flows=3)
    assert len(fa) == 3 and fa.flows_dropped == 2


def test_bidirectional_single_flow():
    fa = flows_for(
        [pm("c", "s", sport=5000, flags=S), pm("s", "c", sport=80, dport=5000, flags=SA)]
    )
    assert len(fa) == 1


def test_flow_order_is_deterministic():
    pk = [pm("a", "b", sport=i, ts=5.0) for i in (3, 1, 2)]
    a = [f.client for f in flows_for(pk).iter_flows()]
    b = [f.client for f in flows_for(reversed(pk)).iter_flows()]
    assert a == b
