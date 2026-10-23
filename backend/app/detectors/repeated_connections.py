from collections import defaultdict

from app.analyzers.flow_analyzer import STATE_ESTABLISHED
from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec
from app.detectors.util import best_weighted_window, confidence_for_ratio, severity_for_ratio


class RepeatedConnectionsRule(DetectionRule):
    id = "repeated_connections"
    name = "Repeated connection attempts"
    description = (
        "Flags a client opening an unusually high number of TCP connections to the same "
        "destination and port within a time window (brute-force-like or polling behavior)."
    )
    limitations = [
        "Counts TCP connections (flows) only; it cannot see authentication results inside "
        "encrypted traffic.",
        "Connections behind NAT or proxies are attributed to the shared address.",
        "Requires timestamps.",
    ]
    false_positive_notes = (
        "Web crawlers, load tests, reverse proxies and chatty polling clients open many short "
        "connections to one service. Raise min_attempts for busy services."
    )
    params = [
        ParamSpec("window_s", 60, 1, 86400, "Sliding window length in seconds."),
        ParamSpec("min_attempts", 50, 2, 1_000_000, "Connections in one window to raise an alert."),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        groups: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto != "TCP" or f.syn == 0 or f.first_ts is None:
                continue
            groups[(f.client[0], f.server[0], f.server[1])].append((f.first_ts, 1, f.state))

        out: list[Finding] = []
        for (src, dst, dport), ev in sorted(groups.items(), key=lambda kv: str(kv[0])):
            ev.sort(key=lambda e: e[0])
            total, lo, hi = best_weighted_window(ev, params["window_s"])
            if total < params["min_attempts"]:
                continue
            win = ev[lo : hi + 1]
            ok = sum(1 for e in win if e[2] == STATE_ESTABLISHED)
            ratio = total / params["min_attempts"]
            failed_share = (len(win) - ok) / len(win)
            out.append(
                Finding(
                    rule_id=self.id,
                    severity=severity_for_ratio(ratio, 3.0, 10.0),
                    title=f"Repeated connections from {src} to {dst}:{dport}",
                    first_seen=win[0][0],
                    last_seen=win[-1][0],
                    src_ips=[src],
                    dst_ips=[dst],
                    evidence={
                        "connections": len(win),
                        "threshold": params["min_attempts"],
                        "window_s": params["window_s"],
                        "dst_port": dport,
                        "handshake_observed": ok,
                        "without_observed_handshake": len(win) - ok,
                        "failed_share": round(failed_share, 3),
                    },
                    explanation=(
                        f"{src} opened {len(win)} TCP connections to {dst}:{dport} within "
                        f"{params['window_s']}s (threshold {params['min_attempts']})."
                    ),
                    why_suspicious=(
                        "Rapid repeated connections to one service can indicate credential "
                        "guessing, service probing or a resource-exhaustion attempt."
                    ),
                    benign_explanations=[
                        "Load testing or monitoring against the service.",
                        "Client without connection reuse (no keep-alive), e.g. a script or crawler.",
                        "Many users behind one NAT address.",
                    ],
                    recommended_steps=[
                        "Identify the client and the service on the destination port.",
                        "Check application/authentication logs for failed attempts in the same period.",
                        "Verify whether the client is expected to be this chatty (keep-alive, polling).",
                        "If abusive, apply rate limiting or temporary blocking (manual action).",
                    ],
                    confidence=confidence_for_ratio(ratio, 0.1 if failed_share > 0.8 else 0.0),
                    key=f"{src}|{dst}|{dport}",
                )
            )
        return out
