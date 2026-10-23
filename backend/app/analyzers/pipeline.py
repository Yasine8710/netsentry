"""Glue: packets -> aggregates + flows -> detection context."""

from collections.abc import Iterable

from app.analyzers.flow_analyzer import FlowAnalyzer
from app.analyzers.models import PacketMeta
from app.analyzers.traffic_aggregator import TrafficAggregator
from app.detectors.base import AnalysisContext


def build_context(
    packets: Iterable[PacketMeta], max_flows: int = 200_000
) -> tuple[AnalysisContext, TrafficAggregator, FlowAnalyzer]:
    agg = TrafficAggregator()
    flows = FlowAnalyzer(max_flows=max_flows)
    for p in packets:
        agg.add(p)
        flows.add(p)
    notes = []
    if flows.flows_dropped:
        notes.append(
            f"Flow table full: {flows.flows_dropped} packets of new flows were not tracked."
        )
    ctx = AnalysisContext(agg, flows.iter_flows(), flows.flows_dropped > 0, notes)
    return ctx, agg, flows
