from statistics import median

from app.detectors.base import AnalysisContext, DetectionRule, Finding, ParamSpec
from app.detectors.util import confidence_for_ratio, severity_for_ratio


class TrafficSpikeRule(DetectionRule):
    id = "traffic_spike"
    name = "Unusual traffic spike"
    description = (
        "Flags time buckets whose packet count is at least `spike_factor` times the median of "
        "the preceding `baseline_buckets` buckets, and at least `min_packets` in absolute terms. "
        "Consecutive spiking buckets are merged into one finding."
    )
    limitations = [
        "The baseline is local (previous buckets only); a capture that starts during a spike has "
        "no baseline until `min_baseline_buckets` buckets have passed.",
        "Bucket width is chosen by the aggregator (1 s, widened automatically for long captures).",
        "Aggregate time series cannot attribute a spike to a specific host; use the traffic "
        "view to investigate.",
        "A sustained increase eventually becomes the new baseline and stops alerting.",
    ]
    false_positive_notes = (
        "Backups, software updates, streaming, batch jobs and scheduled scans cause legitimate "
        "bursts. Raise spike_factor or min_packets to reduce noise."
    )
    params = [
        ParamSpec(
            "baseline_buckets", 30, 3, 5000, "Preceding buckets used for the median baseline."
        ),
        ParamSpec(
            "min_baseline_buckets", 10, 3, 5000, "Buckets of history required before alerting."
        ),
        ParamSpec("spike_factor", 5.0, 1.1, 1000.0, "Multiple of the baseline median.", kind=float),
        ParamSpec("min_packets", 500, 1, 100_000_000, "Minimum packets in a bucket to count."),
    ]

    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        series = ctx.aggregator.series
        dense = series.dense()
        bucket_s = series.bucket_s
        n = params["baseline_buckets"]
        out: list[Finding] = []
        run: list[tuple[float, int, int, float]] = []  # (t, packets, bytes, baseline)

        def flush() -> None:
            if not run:
                return
            peak = max(run, key=lambda r: r[1])
            base = max(peak[3], 1.0)
            ratio = peak[1] / (params["spike_factor"] * base)
            total = sum(r[1] for r in run)
            out.append(
                Finding(
                    rule_id=self.id,
                    severity=severity_for_ratio(ratio, 2.0, 5.0),
                    title=f"Traffic spike: {peak[1]} packets in one {bucket_s:g}s bucket",
                    first_seen=run[0][0],
                    last_seen=run[-1][0] + bucket_s,
                    src_ips=[],
                    dst_ips=[],
                    evidence={
                        "peak_packets": peak[1],
                        "peak_bytes": peak[2],
                        "peak_time": peak[0],
                        "baseline_median_packets": peak[3],
                        "spike_factor": params["spike_factor"],
                        "observed_factor": round(peak[1] / base, 2),
                        "bucket_s": bucket_s,
                        "buckets_in_spike": len(run),
                        "total_packets_in_spike": total,
                    },
                    explanation=(
                        f"Packet rate reached {peak[1]} packets per {bucket_s:g}s, about "
                        f"{peak[1] / base:.1f}x the recent median ({peak[3]:g})."
                    ),
                    why_suspicious=(
                        "Sudden volume increases can accompany floods, scans, data exfiltration "
                        "or malfunctioning devices."
                    ),
                    benign_explanations=[
                        "Backups, updates, large downloads or streaming starting.",
                        "Scheduled batch jobs or monitoring sweeps.",
                    ],
                    recommended_steps=[
                        "Use the traffic view around this time to find the top talkers and protocols.",
                        "Correlate with change windows, backups and scheduled jobs.",
                        "Check other alerts in the same period for scans or floods.",
                    ],
                    confidence=confidence_for_ratio(ratio),
                    key=f"spike|{run[0][0]}",
                )
            )
            run.clear()

        for i, (t, pkts, nbytes) in enumerate(dense):
            hist = [d[1] for d in dense[max(0, i - n) : i]]
            if len(hist) < params["min_baseline_buckets"]:
                flush()
                continue
            base = float(median(hist))
            is_spike = pkts >= params["min_packets"] and pkts >= params["spike_factor"] * max(
                base, 1.0
            )
            if is_spike:
                run.append((t, pkts, nbytes, base))
            else:
                flush()
        flush()
        return out
