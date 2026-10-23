import random

from app.analyzers.models import PacketMeta
from tests.helpers import normal_packets, run


def steady(seconds, per_sec, start=1000.0, length=100):
    return [
        PacketMeta(start + s + k / per_sec, "10.0.0.5", "10.0.0.6", "UDP", length, 1000, 2000)
        for s in range(seconds)
        for k in range(per_sec)
    ]


def burst(at, count, length=100):
    return [
        PacketMeta(at + k / count, "10.0.0.7", "10.0.0.6", "UDP", length, 1, 2)
        for k in range(count)
    ]


RULE = {"traffic_spike"}


def test_steady_traffic_no_spike():
    assert run(steady(60, 20), rule_ids=RULE)[0] == []


def test_spike_detected():
    findings, _ = run(steady(60, 20) + burst(1040.0, 600), rule_ids=RULE)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["peak_packets"] >= 600 and f.first_seen == 1040.0
    assert f.evidence["baseline_median_packets"] == 20


def test_spike_factor_boundary():
    # baseline 20/s -> need >= 5*20 = 100 and >= min_packets
    cfg = {"traffic_spike": {"params": {"min_packets": 100}}}
    assert run(steady(60, 20) + burst(1040.0, 79), cfg, RULE)[0] == []  # 20+79 = 99
    assert len(run(steady(60, 20) + burst(1040.0, 80), cfg, RULE)[0]) == 1  # 20+80 = 100


def test_min_packets_floor():
    # 10x the baseline but below the absolute floor
    assert run(steady(60, 2) + burst(1040.0, 30), rule_ids=RULE)[0] == []


def test_no_baseline_no_alert():
    assert run(burst(1000.0, 5000), rule_ids=RULE)[0] == []


def test_consecutive_spike_buckets_merge():
    pk = steady(60, 20) + burst(1040.0, 600) + burst(1041.0, 700)
    findings, _ = run(pk, rule_ids=RULE)
    assert len(findings) == 1 and findings[0].evidence["buckets_in_spike"] == 2


def dns(src, name, ts, resolver="10.0.0.1"):
    return PacketMeta(ts, src, resolver, "UDP", 80, 4000, 53, dns_qname=name)


def nx(dst, name, ts, resolver="10.0.0.1"):
    return PacketMeta(
        ts, resolver, dst, "UDP", 80, 53, 4000, dns_qname=name, dns_is_response=True, dns_rcode=3
    )


def ok_resp(dst, name, ts, resolver="10.0.0.1"):
    return PacketMeta(
        ts, resolver, dst, "UDP", 80, 53, 4000, dns_qname=name, dns_is_response=True, dns_rcode=0
    )


DNS = {"dns_anomaly"}


def test_benign_dns_not_flagged():
    pk = []
    names = ["example.com", "www.example.com", "mail.google.com", "api.github.com", "cdn.site.org"]
    for i in range(100):
        n = names[i % len(names)]
        pk += [dns("10.0.0.5", n, 1000 + i * 2), ok_resp("10.0.0.5", n, 1000 + i * 2 + 0.01)]
    assert run(pk, rule_ids=DNS)[0] == []
    assert run(normal_packets(), rule_ids=DNS)[0] == []


def test_dns_volume_detected():
    pk = [dns("10.0.0.5", f"host{i % 10}.example.com", 1000 + i * 0.01) for i in range(300)]
    findings, _ = run(pk, rule_ids=DNS)
    assert [f.evidence["kind"] for f in findings] == ["volume"]
    assert findings[0].dst_ips == ["10.0.0.1"]


def test_dns_volume_boundary():
    # 199 queries -> below min_queries
    pk = [dns("10.0.0.5", "a.example.com", 1000 + i * 0.01) for i in range(199)]
    assert run(pk, rule_ids=DNS)[0] == []
    # many queries but slow (1 per second)
    slow = [dns("10.0.0.5", "a.example.com", 1000 + i) for i in range(300)]
    assert run(slow, rule_ids=DNS)[0] == []


def test_nxdomain_detected_and_boundary():
    def pk(n_nx, n_ok=0):
        out = [nx("10.0.0.5", f"zz{i}.example.net", 1000 + i) for i in range(n_nx)]
        out += [ok_resp("10.0.0.5", "ok.example.com", 2000 + i) for i in range(n_ok)]
        return out

    assert [f.evidence["kind"] for f in run(pk(20), rule_ids=DNS)[0]] == ["nxdomain"]
    assert run(pk(19), rule_ids=DNS)[0] == []
    assert run(pk(20, 100), rule_ids=DNS)[0] == []  # 20/120 < 50%


def test_tunneling_like_detected():
    rnd = random.Random(7)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    pk = []
    for i in range(60):
        label = "".join(rnd.choice(chars) for _ in range(40))
        pk.append(dns("10.0.0.5", f"{label}.evil-c2.example", 1000 + i * 5))
    findings, _ = run(pk, rule_ids=DNS)
    assert len(findings) == 1
    e = findings[0].evidence
    assert e["parent_domain"] == "evil-c2.example" and e["unique_subdomains"] == 60
    assert e["avg_subdomain_entropy_bits"] > 3.5


def test_many_short_subdomains_not_tunneling():
    pk = [dns("10.0.0.5", f"h{i}.corp.example", 1000 + i * 5) for i in range(80)]
    assert run(pk, rule_ids=DNS)[0] == []


def test_all_rules_quiet_on_normal_traffic():
    assert run(normal_packets() + steady(60, 5))[0] == []
