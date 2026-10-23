"""Central list of built-in rules. Add new rules here."""

from app.detectors.base import DetectionRule
from app.detectors.dns_anomaly import DnsAnomalyRule
from app.detectors.incomplete_connections import IncompleteConnectionsRule
from app.detectors.port_scan import PortScanRule
from app.detectors.repeated_connections import RepeatedConnectionsRule
from app.detectors.syn_heavy import SynHeavyRule
from app.detectors.traffic_spike import TrafficSpikeRule


def all_rules() -> list[DetectionRule]:
    return [
        PortScanRule(),
        RepeatedConnectionsRule(),
        SynHeavyRule(),
        IncompleteConnectionsRule(),
        TrafficSpikeRule(),
        DnsAnomalyRule(),
    ]
