# API

Base path `/api`. Interactive documentation: run the backend and open `http://localhost:8000/docs` (Swagger UI) or `/openapi.json`.

Errors use `{"detail": "..."}`. Common codes: `400` empty upload, `404` unknown id, `413` upload too large, `415` unsupported file type, `422` invalid content or parameters.

Lists are paginated with `page` (>= 1) and `page_size` (1-200) and return `{items, total, page, page_size}`.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness and version |
| POST | `/api/analyses` | Multipart upload (`file`), analyzes synchronously, returns the analysis (`201`) |
| POST | `/api/analyses/demo` | Analyze the built-in synthetic capture; result has `is_demo: true` |
| GET | `/api/analyses` | List analyses (newest first) |
| GET | `/api/analyses/{id}` | Analysis detail with summary, notes, alert counts |
| DELETE | `/api/analyses/{id}` | Delete an analysis, its alerts and packet rows (`204`) |
| GET | `/api/analyses/{id}/traffic` | Packet metadata. Filters: `q` (IP/DNS name), `proto`, `src`, `dst`, `port` |
| GET | `/api/analyses/{id}/alerts` | Alerts for one analysis. Filters: `severity`, `status`, `rule_id` |
| GET | `/api/alerts` | All alerts. Filters: `analysis_id`, `severity`, `status`, `rule_id`, `q` |
| GET | `/api/alerts/{id}` | Full alert: evidence, explanation, steps, update history, rule documentation |
| PATCH | `/api/alerts/{id}` | Body `{"status"?: ..., "note"?: "..."}`; at least one required |
| GET | `/api/analyses/{id}/reports/json` | Summary, statistics, detections, rules, limitations |
| GET | `/api/analyses/{id}/reports/csv` | Alert records |
| GET | `/api/analyses/{id}/reports/html` | Human-readable, self-contained report |
| GET | `/api/rules` | Rule documentation and effective parameters |
| GET / PUT | `/api/settings` | Read / replace validated settings |
| GET | `/api/overview` | Dashboard aggregates; `include_demo` (default `true`); the response states `includes_demo` |

## Example

```bash
curl -F "file=@data/samples/port_scan.pcap" http://localhost:8000/api/analyses
curl "http://localhost:8000/api/alerts?severity=medium&page_size=5"
curl -X PATCH http://localhost:8000/api/alerts/<id> \
  -H "Content-Type: application/json" \
  -d '{"status":"investigating","note":"Checking with the network team"}'
curl -OJ http://localhost:8000/api/analyses/<id>/reports/html
```

## Settings

`PUT /api/settings` takes the complete object returned by `GET`:

```json
{
  "max_upload_mb": 50,
  "max_packets": 500000,
  "retention_hours": 720,
  "store_packet_rows": 50000,
  "detection": { "port_scan": { "enabled": true, "params": { "min_ports": 30 } } },
  "ui": { "density": "comfortable", "reduced_motion": false, "default_page_size": 25 }
}
```

Unknown fields, unknown rules or parameters, and out-of-range values are rejected with `422`. Changes apply to **new** analyses; each analysis stores the detection configuration it used.
