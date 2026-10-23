from app.analyzers.models import SYN, PacketMeta
from app.analyzers.packet_parser import PacketParser
from app.analyzers.synthetic import normal_traffic, port_scan, write_pcap
from tests.helpers import conn, flatten, normal_packets, run

ATTACKER, VICTIM = "192.0.2.50", "10.0.0.10"


def scan(n, start=1000.0, step=0.01, outcome="none", bidir_extra=True):
    pk = flatten(
        conn(ATTACKER, VICTIM, 50000 + i, 1 + i, start + i * step, outcome) for i in range(n)
    )
    if bidir_extra:
        pk += normal_packets()
    return pk


def ids(findings):
    return [f.rule_id for f in findings]


# ---- sanity ----------------------------------------------------------------
def test_normal_traffic_triggers_nothing():
    findings, _ = run(normal_packets())
    assert findings == []


def test_empty_input_triggers_nothing():
    findings, _ = run([])
    assert findings == []


# ---- port scan -------------------------------------------------------------
def test_port_scan_detected():
    findings, _ = run(scan(25), rule_ids={"port_scan"})
    assert ids(findings) == ["port_scan"]
    f = findings[0]
    assert f.src_ips == [ATTACKER] and f.dst_ips == [VICTIM]
    assert f.evidence["distinct_ports"] == 25 and f.evidence["pattern"] == "vertical"
    assert f.first_seen == 1000.0 and f.last_seen > f.first_seen


def test_port_scan_threshold_boundary():
    assert run(scan(19), rule_ids={"port_scan"})[0] == []
    assert len(run(scan(20), rule_ids={"port_scan"})[0]) == 1


def test_port_scan_custom_threshold():
    cfg = {"port_scan": {"params": {"min_ports": 5}}}
    assert len(run(scan(5), cfg, {"port_scan"})[0]) == 1
    assert run(scan(4), cfg, {"port_scan"})[0] == []


def test_port_scan_window_boundary():
    # 20 ports; first at t=1000, last at 1000+span
    def pk(span):
        return flatten(
            conn(ATTACKER, VICTIM, 50000 + i, 1 + i, 1000 + span * i / 19, "none")
            for i in range(20)
        )

    cfg = {"port_scan": {"params": {"window_s": 60}}}
    assert len(run(pk(60.0) + normal_packets(), cfg, {"port_scan"})[0]) == 1
    assert run(pk(60.5) + normal_packets(), cfg, {"port_scan"})[0] == []


def test_completed_connections_are_not_scans():
    findings, _ = run(scan(40, outcome="ok"), rule_ids={"port_scan"})
    assert findings == []


def test_reset_probes_counted_and_boost_confidence():
    none_f = run(scan(30), rule_ids={"port_scan"})[0][0]
    rst_f = run(scan(30, outcome="rst"), rule_ids={"port_scan"})[0][0]
    assert rst_f.evidence["reset_by_responder"] == 30
    assert rst_f.confidence > none_f.confidence


def test_host_sweep_detected():
    pk = flatten(
        conn(ATTACKER, f"10.1.0.{i}", 50000 + i, 445, 1000 + i * 0.05, "none") for i in range(25)
    )
    findings, _ = run(pk + normal_packets(), rule_ids={"port_scan"})
    assert len(findings) == 1 and findings[0].evidence["pattern"] == "sweep"
    assert findings[0].evidence["distinct_hosts"] == 25


def test_one_directional_capture_lowers_confidence():
    bi = run(scan(30), rule_ids={"port_scan"})[0][0]
    uni = run(scan(30, bidir_extra=False), rule_ids={"port_scan"})[0][0]
    assert uni.evidence["one_directional_capture"] and uni.confidence < bi.confidence


def test_port_scan_from_real_pcap(tmp_path):
    pk = port_scan(ATTACKER, VICTIM, range(1, 41)) + normal_traffic()
    f = write_pcap(tmp_path / "scan.pcap", pk)
    findings, _ = run(list(PacketParser().parse(f)), rule_ids={"port_scan"})
    assert len(findings) == 1 and findings[0].evidence["distinct_ports"] == 40


# ---- repeated connections ---------------------------------------------------
def repeated(n, span=10.0, outcome="none"):
    return flatten(
        conn("192.0.2.9", VICTIM, 30000 + i, 22, 1000 + span * i / max(n - 1, 1), outcome)
        for i in range(n)
    )


def test_repeated_connections_detected():
    findings, _ = run(repeated(60) + normal_packets(), rule_ids={"repeated_connections"})
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["dst_port"] == 22 and f.evidence["connections"] == 60


def test_repeated_connections_boundary():
    assert run(repeated(49), rule_ids={"repeated_connections"})[0] == []
    assert len(run(repeated(50), rule_ids={"repeated_connections"})[0]) == 1


def test_repeated_spread_over_time_not_flagged():
    # 50 connections but 10 minutes apart -> never 50 inside 60 s
    assert run(repeated(50, span=600.0), rule_ids={"repeated_connections"})[0] == []


def test_repeated_failed_share_in_evidence():
    f = run(repeated(60), rule_ids={"repeated_connections"})[0][0]
    assert f.evidence["failed_share"] == 1.0


# ---- SYN heavy ---------------------------------------------------------------
def flood(n, outcome="none", span=5.0):
    return flatten(
        conn(
            f"198.51.100.{i % 250}", VICTIM, 20000 + i, 80, 1000 + span * i / max(n - 1, 1), outcome
        )
        for i in range(n)
    )


def test_syn_heavy_detected():
    findings, _ = run(flood(250) + normal_packets(), rule_ids={"syn_heavy"})
    assert len(findings) == 1 and findings[0].evidence["distinct_sources"] == 250


def test_syn_heavy_boundary():
    assert run(flood(199) + normal_packets(), rule_ids={"syn_heavy"})[0] == []
    assert len(run(flood(200) + normal_packets(), rule_ids={"syn_heavy"})[0]) == 1


def test_syn_burst_with_completed_handshakes_not_flagged():
    findings, _ = run(flood(300, outcome="ok"), rule_ids={"syn_heavy"})
    assert findings == []


def test_syn_retransmissions_count():
    pk = [
        PacketMeta(1000 + i * 0.01, "1.1.1.1", VICTIM, "TCP", 60, 5000, 80, SYN) for i in range(250)
    ]
    pk += normal_packets()
    findings, _ = run(pk, rule_ids={"syn_heavy"})
    assert len(findings) == 1 and findings[0].evidence["syn_packets"] == 250


# ---- incomplete connections -------------------------------------------------
def failing(n_fail, n_ok=0):
    pk = flatten(
        conn("192.0.2.77", VICTIM, 30000 + i, 8080, 1000 + i, "none") for i in range(n_fail)
    )
    pk += flatten(conn("192.0.2.77", VICTIM, 40000 + i, 80, 2000 + i, "ok") for i in range(n_ok))
    return pk + normal_packets()


def test_incomplete_detected():
    findings, _ = run(failing(40, 5), rule_ids={"incomplete_connections"})
    assert len(findings) == 1
    assert findings[0].evidence["incomplete"] == 40 and findings[0].src_ips == ["192.0.2.77"]


def test_incomplete_count_boundary():
    assert run(failing(29), rule_ids={"incomplete_connections"})[0] == []
    assert len(run(failing(30), rule_ids={"incomplete_connections"})[0]) == 1


def test_incomplete_ratio_boundary():
    # 30 failed / 100 attempts = 30% < 70%
    assert run(failing(30, 70), rule_ids={"incomplete_connections"})[0] == []


def test_incomplete_skipped_for_one_directional_capture():
    pk = flatten(conn("192.0.2.77", VICTIM, 30000 + i, 8080, 1000 + i, "none") for i in range(50))
    findings, ctx = run(pk, rule_ids={"incomplete_connections"})
    assert findings == [] and any("skipped" in n for n in ctx.notes)


# ---- determinism -------------------------------------------------------------
def test_determinism_same_and_reordered_input():
    pk = scan(30) + repeated(60) + flood(250)
    a, _ = run(pk)
    b, _ = run(pk)
    c, _ = run(list(reversed(pk)))
    fp = lambda fs: [(f.rule_id, f.key, f.first_seen, f.severity) for f in fs]  # noqa: E731
    assert fp(a) == fp(b) == fp(c) and len(a) >= 3
