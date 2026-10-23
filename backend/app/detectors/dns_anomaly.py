import math
from collections import Counter, defaultdict

from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec, Severity
from app.detectors.util import confidence_for_ratio, severity_for_ratio


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def parent_domain(qname: str) -> str:
    """Naive last-two-labels grouping (no public-suffix list; co.uk etc. group coarsely)."""
    labels = qname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname


class DnsAnomalyRule(DetectionRule):
    id = "dns_anomaly"
    name = "DNS query anomalies"
    description = (
        "Per host: (1) very high DNS query rate, (2) many NXDOMAIN answers, (3) many unique, "
        "long, high-entropy subdomains under one parent domain (pattern consistent with DNS "
        "tunneling or algorithmically generated names)."
    )
    limitations = [
        "Plain DNS on UDP only (encrypted DNS such as DoH/DoT is not visible).",
        "Only the first question of each message is examined.",
        "Parent domains are grouped by the last two labels without a public-suffix list.",
        "Query rate uses the host's first-to-last query span, so bursts inside long captures "
        "are averaged out.",
        "Entropy is a heuristic and cannot prove a name is generated.",
    ]
    false_positive_notes = (
        "CDNs, anti-virus and cloud services legitimately use many long, random-looking "
        "subdomains; resolvers and busy proxies issue high query volumes. Raise thresholds for "
        "such environments."
    )
    params = [
        ParamSpec("min_queries", 200, 2, 100_000_000, "Minimum queries before a rate alert."),
        ParamSpec(
            "max_qps", 20.0, 0.1, 100_000.0, "Average queries per second to alert.", kind=float
        ),
        ParamSpec("min_nxdomain", 20, 2, 100_000_000, "NXDOMAIN answers needed to alert."),
        ParamSpec("min_nxdomain_ratio", 0.5, 0.0, 1.0, "NXDOMAIN share of answers.", kind=float),
        ParamSpec("min_unique_subdomains", 50, 2, 1_000_000, "Unique subdomains under one parent."),
        ParamSpec("min_avg_subdomain_len", 15, 1, 253, "Average subdomain length (characters)."),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        out: list[Finding] = []
        for src, s in sorted(ctx.aggregator.dns_by_source.items()):
            resolvers = sorted(s.servers)
            span = (
                (s.last_ts - s.first_ts)
                if s.first_ts is not None and s.last_ts is not None
                else None
            )

            if span is not None and s.queries >= params["min_queries"]:
                qps = s.queries / max(span, 1.0)
                if qps >= params["max_qps"]:
                    ratio = qps / params["max_qps"]
                    out.append(
                        self._finding(
                            src,
                            resolvers,
                            "volume",
                            s.first_ts,
                            s.last_ts,
                            severity_for_ratio(ratio, 3.0, 10.0),
                            f"High DNS query rate from {src}",
                            {
                                "queries": s.queries,
                                "avg_qps": round(qps, 2),
                                "threshold_qps": params["max_qps"],
                                "unique_names": len(s.qnames),
                            },
                            f"{src} issued {s.queries} DNS queries at about {qps:.1f}/s.",
                            "Very high query rates can indicate malware beaconing, tunneling or a "
                            "misbehaving resolver loop.",
                            confidence_for_ratio(ratio, 0.0, 0.1),
                        )
                    )

            if (
                s.nxdomain >= params["min_nxdomain"]
                and s.responses_to
                and s.nxdomain / s.responses_to >= params["min_nxdomain_ratio"]
            ):
                share = s.nxdomain / s.responses_to
                ratio = s.nxdomain / params["min_nxdomain"]
                out.append(
                    self._finding(
                        src,
                        resolvers,
                        "nxdomain",
                        s.first_ts,
                        s.last_ts,
                        severity_for_ratio(ratio, 3.0, 10.0),
                        f"Many NXDOMAIN responses to {src}",
                        {
                            "nxdomain": s.nxdomain,
                            "responses": s.responses_to,
                            "nxdomain_share": round(share, 3),
                            "threshold": params["min_nxdomain"],
                        },
                        f"{s.nxdomain} of {s.responses_to} DNS answers received by {src} "
                        f"({share:.0%}) were NXDOMAIN (name does not exist).",
                        "Lookups for many non-existent names are typical of domain-generation "
                        "algorithms, typo-squatting probes or subdomain brute forcing.",
                        confidence_for_ratio(ratio),
                    )
                )

            out += self._tunneling(src, resolvers, s, params)
        return out

    def _tunneling(self, src, resolvers, s, params):
        groups: dict[str, set] = defaultdict(set)
        for q in sorted(s.qnames):
            labels = q.split(".")
            if len(labels) > 2:
                groups[parent_domain(q)].add(".".join(labels[:-2]))
        found = []
        for parent, subs in sorted(groups.items()):
            if len(subs) < params["min_unique_subdomains"]:
                continue
            avg_len = sum(len(x) for x in subs) / len(subs)
            if avg_len < params["min_avg_subdomain_len"]:
                continue
            avg_entropy = sum(shannon_entropy(x.replace(".", "")) for x in subs) / len(subs)
            ratio = len(subs) / params["min_unique_subdomains"]
            sev = max(severity_for_ratio(ratio, 3.0, 10.0), Severity.MEDIUM, key=lambda v: v.rank)
            found.append(
                self._finding(
                    src,
                    resolvers,
                    f"tunnel|{parent}",
                    s.first_ts,
                    s.last_ts,
                    sev,
                    f"Possible DNS tunneling/DGA-like activity from {src} via {parent}",
                    {
                        "parent_domain": parent,
                        "unique_subdomains": len(subs),
                        "avg_subdomain_length": round(avg_len, 1),
                        "avg_subdomain_entropy_bits": round(avg_entropy, 2),
                        "threshold_unique": params["min_unique_subdomains"],
                    },
                    f"{src} queried {len(subs)} unique long subdomains of {parent} "
                    f"(avg length {avg_len:.0f}, entropy {avg_entropy:.1f} bits/char).",
                    "Encoding data into many unique, long subdomains is how DNS tunneling and some "
                    "malware command channels work.",
                    confidence_for_ratio(ratio, 0.1 if avg_entropy >= 3.5 else 0.0),
                )
            )
        return found

    def _finding(
        self,
        src,
        resolvers,
        kind,
        first,
        last,
        severity,
        title,
        evidence,
        explanation,
        why,
        confidence,
    ):
        return Finding(
            rule_id=self.id,
            severity=severity,
            title=title,
            first_seen=first,
            last_seen=last,
            src_ips=[src],
            dst_ips=resolvers,
            evidence={"kind": kind.split("|")[0], **evidence},
            explanation=explanation,
            why_suspicious=why,
            benign_explanations=[
                "CDN, cloud, antivirus or telemetry services using long or random-looking names.",
                "Busy resolver, proxy or NAT gateway aggregating many users.",
                "Misconfigured software retrying lookups.",
            ],
            recommended_steps=[
                "Identify the host and the process generating the queries.",
                "Review the queried names in the traffic view and check their reputation.",
                "Check the resolver's logs for the same host and period.",
                "Consider sinkholing or blocking the parent domain if confirmed malicious (manual).",
            ],
            confidence=confidence,
            key=f"{kind}|{src}",
        )
