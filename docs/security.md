# Security

NetSentry is a **defensive, offline analysis tool**. It performs no scanning, exploitation, credential handling, live capture, traffic blocking or modification.

## Deployment assumptions (read this first)

- **There is no authentication or authorization.** Anyone who can reach the API can upload files, read every analysis, change settings and delete data.
- Run it on a trusted workstation or an isolated network. The provided `docker-compose.yml` binds the UI to `127.0.0.1` only.
- **Do not expose it to the internet or an untrusted network.** If you must share it, put it behind an authenticating reverse proxy (SSO / mTLS / VPN) with TLS and rate limiting. Adding built-in authentication is on the roadmap.
- Captures often contain sensitive data (addresses, DNS names). NetSentry stores only header-level metadata, but treat the database and reports as sensitive.

## Implemented controls

| Area | Control |
|---|---|
| Upload size | Middleware rejects oversized `Content-Length` and aborts streaming bodies over the limit **before** buffering; the service enforces the limit again while writing. Configurable 1-500 MB. |
| File validation | Extension allow-list and magic-byte check; a file is never executed or imported. Parsing is done by Scapy's capture reader only. |
| Filenames | Uploads are stored under a generated `<uuid>.upload` name. The client's filename is sanitized and used only as a display label. No API accepts a filesystem path. |
| Cleanup | The temp file is removed in a `finally` block; orphans older than an hour are swept; analyses expire after `retention_hours`. |
| Resource limits | Packet cap, parse time limit, flow-table cap, counter key caps, time-series bucket cap, per-analysis stored-row cap, pagination limit (200). |
| Data minimization | Packet payloads are never stored or exported. Only headers, TCP flags, ICMP type and the DNS question name are kept. |
| Output encoding | The HTML report escapes every dynamic value, contains no scripts and is served with a restrictive `Content-Security-Policy`; the UI renders data through React (escaped). CSV export neutralizes spreadsheet-formula injection. Reports download with `X-Content-Type-Options: nosniff`. |
| CORS | Explicit origin allow-list from `NETSENTRY_CORS_ORIGINS`; no wildcard. |
| SQL | SQLAlchemy parameter binding throughout; `LIKE` wildcards in user search strings are escaped. |
| Configuration | Environment based (`NETSENTRY_*`), no secrets in the repo, `.env` ignored. Settings (thresholds, limits) are validated server-side with ranges. |
| Container | Backend runs as a non-root user; data lives in a named volume. |

## Remaining risks

- **No auth / no multi-tenancy** (see above). Notes and statuses are not attributed to a user.
- **Parser attack surface.** Scapy dissects untrusted packet bytes. A crafted capture could trigger a parser bug or heavy CPU use; the time limit and packet cap bound but do not eliminate this. Run in a container or VM when analyzing hostile captures.
- **Synchronous analysis** occupies a worker thread for up to the time limit; many concurrent uploads can exhaust workers (no rate limiting).
- **SQLite** is single-writer and unsuited to heavy concurrent use.
- **No TLS** in the provided compose file.
- Detection results are heuristics and can be wrong in both directions; do not automate blocking decisions from them.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue.
