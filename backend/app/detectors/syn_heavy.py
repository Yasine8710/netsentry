from collections import defaultdict

from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec
from app.detectors.util import best_weighted_window, confidence_for_ratio, severity_for_ratio


class SynHeavyRule(DetectionRule):
    id = "syn_heavy"
    name = "SYN-heavy traffic"
    description = (
        "Flags a destination receiving an unusually high number of TCP SYN packets in a window, "
        "especially when few connections complete (pattern consistent with a SYN flood)."
    )
    limitations = [
        "SYN time is approximated by the flow's first packet; retransmitted SYNs are counted at "
        "that time.",
        "Cannot distinguish a flood from a legitimate burst such as a traffic surge or crawler.",
        "Spoofed sources appear as many distinct clients.",
        "Requires timestamps.",
    ]
    false_positive_notes = (
        "Flash crowds, load tests and service restarts (clients reconnecting) produce SYN bursts. "
        "A high completion ratio makes a flood less likely."
    )
    params = [
        ParamSpec("window_s", 10, 1, 3600, "Sliding window length in seconds."),
        ParamSpec("min_syns", 200, 2, 10_000_000, "SYN packets to one destination per window."),
        ParamSpec(
            "max_completion_ratio",
            0.5,
            0.0,
            1.0,
            "Alert only if completed/attempted connections in the window is at or below this.",
            kind=float,
        ),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        groups: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto != "TCP" or f.syn == 0 or f.first_ts is None:
                continue
            groups[(f.server[0], f.server[1])].append(
                (f.first_ts, f.syn, f.client[0], f.state == "handshake_observed")
            )

        out: list[Finding] = []
        for (dst, dport), ev in sorted(groups.items(), key=lambda kv: str(kv[0])):
            ev.sort(key=lambda e: (e[0], e[2]))
            total, lo, hi = best_weighted_window(ev, params["window_s"])
            if total < params["min_syns"]:
                continue
            win = ev[lo : hi + 1]
            completed = sum(1 for e in win if e[3])
            completion = completed / len(win)
            if completion > params["max_completion_ratio"]:
                continue
            sources = sorted({e[2] for e in win})
            ratio = total / params["min_syns"]
            out.append(
                Finding(
                    rule_id=self.id,
                    severity=severity_for_ratio(ratio, 3.0, 10.0),
                    title=f"SYN-heavy traffic towards {dst}:{dport}",
                    first_seen=win[0][0],
                    last_seen=win[-1][0],
                    src_ips=sources[:50],
                    dst_ips=[dst],
                    evidence={
                        "syn_packets": total,
                        "threshold": params["min_syns"],
                        "window_s": params["window_s"],
                        "connections": len(win),
                        "completed_handshakes": completed,
                        "completion_ratio": round(completion, 3),
                        "distinct_sources": len(sources),
                        "dst_port": dport,
                    },
                    explanation=(
                        f"{dst}:{dport} received {total} SYN packets from {len(sources)} source(s) "
                        f"within {params['window_s']}s; only {completed} of {len(win)} connections "
                        "show a completed handshake in this capture."
                    ),
                    why_suspicious=(
                        "Many connection requests that are never completed can exhaust a server's "
                        "connection table (SYN flood)."
                    ),
                    benign_explanations=[
                        "Legitimate traffic burst or flash crowd.",
                        "Clients reconnecting after a service restart.",
                        "Capture point sees only one direction, hiding completed handshakes.",
                    ],
                    recommended_steps=[
                        "Check the target's connection-table and SYN-queue metrics.",
                        "Look for the same period in server and load-balancer logs.",
                        "Verify SYN cookies / rate limits are enabled on the target.",
                        "Compare the source list against expected clients.",
                    ],
                    confidence=confidence_for_ratio(
                        ratio,
                        0.1 if completion < 0.1 else 0.0,
                        0.0 if ctx.has_reverse_traffic else 0.25,
                    ),
                    key=f"{dst}|{dport}",
                )
            )
        return out
