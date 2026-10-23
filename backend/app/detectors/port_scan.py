from collections import defaultdict

from app.analyzers.flow_analyzer import STATE_NO_RESPONSE, STATE_REFUSED
from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec
from app.detectors.util import best_window, confidence_for_ratio, severity_for_ratio

PROBE_STATES = {STATE_NO_RESPONSE, STATE_REFUSED}

STEPS = [
    "Confirm whether the source is an authorized scanner, monitoring system or asset-discovery tool.",
    "Check firewall/IDS logs for the same source around the first/last observed times.",
    "Review which targeted ports are exposed and whether any responded (handshake observed).",
    "If unauthorized, consider rate-limiting or blocking the source at the perimeter (manual action).",
]


class PortScanRule(DetectionRule):
    id = "port_scan"
    name = "Port scan / host sweep"
    description = (
        "Flags a source that sends unanswered or reset TCP connection attempts to many distinct "
        "ports on one host (vertical scan) or to the same port on many hosts (horizontal sweep) "
        "inside a sliding time window."
    )
    limitations = [
        "Only TCP SYN-style probing is evaluated; UDP and ICMP scans are not detected.",
        "Needs timestamps; flows without a timestamp are ignored.",
        "Slow scans spread over longer than the window will not be detected.",
        "A flow's outcome is inferred from captured packets only; a capture taken at one point "
        "may miss replies.",
        "Port reuse by the same 5-tuple is merged into a single flow.",
    ]
    false_positive_notes = (
        "Vulnerability scanners, asset inventory tools, load balancers health checks and busy "
        "clients behind NAT can look like scans. Lower thresholds find more but raise false "
        "positives; higher thresholds miss small scans."
    )
    params = [
        ParamSpec("window_s", 60, 1, 86400, "Sliding window length in seconds."),
        ParamSpec("min_ports", 20, 2, 65535, "Distinct ports on one host to raise an alert."),
        ParamSpec("min_hosts", 20, 2, 65535, "Distinct hosts on one port to raise a sweep alert."),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        vertical: dict[tuple, list] = defaultdict(list)
        horizontal: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto != "TCP" or f.state not in PROBE_STATES or f.first_ts is None:
                continue
            src, (dst, dport) = f.client[0], f.server
            vertical[(src, dst)].append((f.first_ts, dport, f.state, dst))
            horizontal[(src, dport)].append((f.first_ts, dst, f.state, dport))

        out: list[Finding] = []
        for (src, dst), ev in sorted(vertical.items()):
            out += self._check(
                ctx, params, ev, params["min_ports"], "ports", src, [dst], "vertical"
            )
        for (src, dport), ev in sorted(horizontal.items()):
            out += self._check(
                ctx, params, ev, params["min_hosts"], "hosts", src, None, "sweep", dport
            )
        return out

    def _check(self, ctx, params, events, threshold, unit, src, dsts, kind, dport=None):
        events.sort(key=lambda e: (e[0], str(e[1])))
        distinct, lo, hi = best_window(events, params["window_s"])
        if distinct < threshold:
            return []
        win = events[lo : hi + 1]
        values = sorted({e[1] for e in win}, key=str)
        refused = sum(1 for e in win if e[2] == STATE_REFUSED)
        ratio = distinct / threshold
        targets = dsts if dsts is not None else values
        bonus = 0.1 if refused else 0.0
        penalty = 0.0 if ctx.has_reverse_traffic else 0.2
        if kind == "vertical":
            title = f"Possible port scan from {src} against {dsts[0]}"
            summary = f"{src} sent unanswered or reset TCP connection attempts to {distinct} distinct ports on {dsts[0]}"
        else:
            title = f"Possible host sweep from {src} on port {dport}"
            summary = f"{src} sent unanswered or reset TCP connection attempts to port {dport} on {distinct} distinct hosts"
        return [
            Finding(
                rule_id=self.id,
                severity=severity_for_ratio(ratio),
                title=title,
                first_seen=win[0][0],
                last_seen=win[-1][0],
                src_ips=[src],
                dst_ips=list(targets)[:50],
                evidence={
                    "pattern": kind,
                    f"distinct_{unit}": distinct,
                    "threshold": threshold,
                    "window_s": params["window_s"],
                    "probe_flows": len(win),
                    "reset_by_responder": refused,
                    "no_reply_observed": len(win) - refused,
                    "sample_values": [str(v) for v in values[:15]],
                    "one_directional_capture": not ctx.has_reverse_traffic,
                },
                explanation=f"{summary} within {params['window_s']}s (threshold {threshold}).",
                why_suspicious=(
                    "Touching many different ports or hosts in a short time without completing "
                    "connections is the typical footprint of reconnaissance."
                ),
                benign_explanations=[
                    "Authorized vulnerability scanner or asset-discovery tool.",
                    "Network monitoring or load-balancer health checks.",
                    "A misconfigured client retrying against many addresses.",
                ],
                recommended_steps=STEPS,
                confidence=confidence_for_ratio(ratio, bonus, penalty),
                key=f"{kind}|{src}|{dsts[0] if dsts else dport}",
            )
        ]
