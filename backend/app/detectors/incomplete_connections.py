from collections import defaultdict

from app.analyzers.flow_analyzer import STATE_NO_RESPONSE, STATE_REFUSED
from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec
from app.detectors.util import confidence_for_ratio, severity_for_ratio

FAILED = {STATE_NO_RESPONSE, STATE_REFUSED}


class IncompleteConnectionsRule(DetectionRule):
    id = "incomplete_connections"
    name = "High rate of incomplete connections"
    description = (
        "Flags a client whose TCP connection attempts mostly show no completed handshake "
        "(no reply observed or reset by the responder)."
    )
    limitations = [
        "Skipped entirely for one-directional captures, where replies are simply not visible.",
        "'No reply observed' is not proof the connection failed; packets may have been lost "
        "or captured elsewhere.",
        "Captures that begin or end mid-connection produce partial flows, which are not counted "
        "as failures.",
    ]
    false_positive_notes = (
        "Firewalled services, retrying clients and unavailable servers produce failed connections "
        "without any malicious intent. Raise min_failed or min_ratio in noisy environments."
    )
    params = [
        ParamSpec("min_failed", 30, 2, 10_000_000, "Failed/incomplete connections per client."),
        ParamSpec(
            "min_ratio",
            0.7,
            0.0,
            1.0,
            "Minimum share of the client's attempts that did not complete.",
            kind=float,
        ),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        if not ctx.has_reverse_traffic:
            ctx.notes.append(
                "incomplete_connections skipped: capture contains no responder-side packets."
            )
            return []
        by_src: dict[str, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto == "TCP" and f.syn > 0:
                by_src[f.client[0]].append(f)

        out: list[Finding] = []
        for src, flows in sorted(by_src.items()):
            failed = [f for f in flows if f.state in FAILED]
            share = len(failed) / len(flows)
            if len(failed) < params["min_failed"] or share < params["min_ratio"]:
                continue
            resets = sum(1 for f in failed if f.state == STATE_REFUSED)
            ratio = len(failed) / params["min_failed"]
            times = [f.first_ts for f in failed if f.first_ts is not None]
            dsts = sorted({f.server[0] for f in failed})
            out.append(
                Finding(
                    rule_id=self.id,
                    severity=severity_for_ratio(ratio, 3.0, 10.0),
                    title=f"Many incomplete connections from {src}",
                    first_seen=min(times) if times else None,
                    last_seen=max(f.last_ts for f in failed if f.last_ts is not None)
                    if times
                    else None,
                    src_ips=[src],
                    dst_ips=dsts[:50],
                    evidence={
                        "attempts": len(flows),
                        "incomplete": len(failed),
                        "incomplete_share": round(share, 3),
                        "reset_by_responder": resets,
                        "no_reply_observed": len(failed) - resets,
                        "distinct_destinations": len(dsts),
                        "threshold_failed": params["min_failed"],
                        "threshold_ratio": params["min_ratio"],
                    },
                    explanation=(
                        f"{len(failed)} of {src}'s {len(flows)} TCP connection attempts "
                        f"({share:.0%}) show no completed handshake in this capture."
                    ),
                    why_suspicious=(
                        "A high failure rate can indicate probing of closed/filtered ports or "
                        "attempts against services that do not exist."
                    ),
                    benign_explanations=[
                        "Target service is down or firewalled and the client keeps retrying.",
                        "Misconfigured application pointing at the wrong host or port.",
                        "Asymmetric routing hiding some replies from the capture point.",
                    ],
                    recommended_steps=[
                        "Check whether the destinations should be reachable from this client.",
                        "Inspect the client for a misbehaving application or malware.",
                        "Review firewall logs for drops from this source.",
                    ],
                    confidence=confidence_for_ratio(ratio, 0.05 if resets else 0.0),
                    key=src,
                )
            )
        return out
