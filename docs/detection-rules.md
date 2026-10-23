# Detection rules

All rules are heuristics over packet headers and flow statistics. A finding means "this pattern exceeded the configured threshold", **not** "an attack happened". Thresholds are configurable in **Settings** (or `PUT /api/settings`) and validated by the backend. The comparison is always **inclusive**: a value equal to the threshold triggers.

## Alert fields

Every alert carries: unique id, rule, severity (`informational`, `low`, `medium`, `high`, `critical`), first/last observed timestamps, source and destination IPs where relevant, supporting statistics (`evidence`), an explanation, why it may be suspicious, possible benign explanations, recommended investigation steps, an evidence-strength indicator, a status (`new`, `investigating`, `resolved`, `false_positive`) and analyst notes.

### Evidence strength (confidence)

A number from 0.1 to 0.95 with a label: `low` (< 0.4), `medium` (0.4 to < 0.7), `high` (>= 0.7).

It measures **how clearly the observed pattern exceeds the threshold** (0.4 exactly at the threshold, rising to 0.8 at five times the threshold) plus small adjustments (e.g. +0.1 when responders sent resets, -0.2 when the capture shows no responder traffic). It is **not** the probability that the activity is malicious.

### Severity

Derived from how far the observation exceeds the threshold (ratio = observed / threshold). Most rules: `low` below 2x, `medium` from 2x, `high` from 5x (connection-count and DNS rules use 3x / 10x; DNS tunneling is at least `medium`). Severity expresses how unusual the volume is, not the damage done. `critical` is reserved and not emitted by the built-in rules.

## Rules

### `port_scan`: Port scan / host sweep
Unanswered or reset TCP connection attempts from one source to many distinct **ports on one host** (vertical) or the **same port on many hosts** (sweep) inside a sliding window.

| Parameter | Default | Range |
|---|---|---|
| `window_s` | 60 | 1-86400 |
| `min_ports` | 20 | 2-65535 |
| `min_hosts` | 20 | 2-65535 |

*Limitations*: TCP only; needs timestamps; scans slower than the window are missed; outcomes are inferred from captured packets; port reuse is merged into one flow.
*False positives*: vulnerability scanners, health checks, NAT gateways. Lower thresholds find smaller scans but flag more benign hosts.

### `repeated_connections`: Repeated connection attempts
One client opening many TCP connections to the same destination and port in a window (credential-guessing-like, or polling clients without keep-alive).

| Parameter | Default | Range |
|---|---|---|
| `window_s` | 60 | 1-86400 |
| `min_attempts` | 50 | 2-1,000,000 |

*Limitations*: cannot see authentication results in encrypted traffic; NAT/proxy addresses are shared. *False positives*: crawlers, load tests, reverse proxies.

### `syn_heavy`: SYN-heavy traffic
A destination receiving many SYN packets in a window where few connections complete (SYN-flood-like).

| Parameter | Default | Range |
|---|---|---|
| `window_s` | 10 | 1-3600 |
| `min_syns` | 200 | 2-10,000,000 |
| `max_completion_ratio` | 0.5 | 0-1 |

*Limitations*: SYN time is approximated by the flow's first packet; cannot tell a flood from a flash crowd; spoofed sources look like many clients. Confidence is reduced when the capture contains no responder traffic.

### `incomplete_connections`: High rate of incomplete connections
A client whose TCP attempts mostly show no completed handshake (no reply observed, or reset by the responder).

| Parameter | Default | Range |
|---|---|---|
| `min_failed` | 30 | 2-10,000,000 |
| `min_ratio` | 0.7 | 0-1 |

*Limitations*: **skipped for one-directional captures** (replies would be invisible, so "failure" cannot be inferred); "no reply observed" is not proof of failure; mid-connection captures are not counted as failures.

### `traffic_spike`: Unusual traffic spike
A time bucket whose packet count is at least `spike_factor` times the median of the previous `baseline_buckets` buckets and at least `min_packets`. Consecutive spiking buckets merge.

| Parameter | Default | Range |
|---|---|---|
| `baseline_buckets` | 30 | 3-5000 |
| `min_baseline_buckets` | 10 | 3-5000 |
| `spike_factor` | 5.0 | 1.1-1000 |
| `min_packets` | 500 | 1-100,000,000 |

*Limitations*: no baseline until `min_baseline_buckets` buckets exist; a sustained increase becomes the new baseline; aggregate series cannot attribute a spike to a host (use the traffic view). *False positives*: backups, updates, batch jobs.

### `dns_anomaly`: DNS query anomalies
Per host: very high query rate; many NXDOMAIN answers; many unique, long, high-entropy subdomains under one parent domain (DNS-tunneling / DGA-like).

| Parameter | Default | Range |
|---|---|---|
| `min_queries` | 200 | 2-100,000,000 |
| `max_qps` | 20 | 0.1-100,000 |
| `min_nxdomain` | 20 | 2-100,000,000 |
| `min_nxdomain_ratio` | 0.5 | 0-1 |
| `min_unique_subdomains` | 50 | 2-1,000,000 |
| `min_avg_subdomain_len` | 15 | 1-253 |

*Limitations*: plain DNS over UDP only (DoH/DoT invisible); first question per message; parent domain = last two labels (no public-suffix list); rate is averaged over the host's query span; entropy is a heuristic. *False positives*: CDNs, antivirus and telemetry use long random-looking names; resolvers and proxies are busy by design.

## Adding a rule

1. Subclass `DetectionRule` in `backend/app/detectors/`, define `id`, `name`, `description`, `limitations`, `false_positive_notes`, `params` (`ParamSpec` with ranges) and `detect()`.
2. Register it in `registry.py`.
3. Add tests: a positive case, a benign case, threshold boundaries (n-1 and n), and a determinism check.
