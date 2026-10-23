import { FlaskConical, Upload } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ProtocolChart, SeverityBars, TrafficChart } from '../components/charts'
import {
  DemoBadge,
  EmptyState,
  ErrorState,
  Loading,
  Notice,
  Panel,
  SeverityBadge,
  StatCard,
  StatusBadge,
  btnPrimary,
  btnSecondary,
  td,
  th,
} from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { formatBytes, formatIso, formatNumber, formatTs } from '../utils/format'

function readPref(): boolean {
  try {
    return localStorage.getItem('ns.includeDemo') !== 'false'
  } catch {
    return true
  }
}

export default function Overview() {
  const [includeDemo, setIncludeDemo] = useState(readPref)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { data, error, loading, reload } = useAsync(() => api.overview(includeDemo), [includeDemo])

  function toggleDemo(v: boolean) {
    setIncludeDemo(v)
    try {
      localStorage.setItem('ns.includeDemo', String(v))
    } catch {
      /* storage unavailable */
    }
  }

  async function loadDemo() {
    setBusy(true)
    setActionError(null)
    try {
      await api.createDemo()
      toggleDemo(true)
      reload()
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Could not create demo analysis')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Overview</h1>
          <p className="text-sm text-slate-400">Aggregated results from analyzed captures.</p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={includeDemo}
            onChange={(e) => toggleDemo(e.target.checked)}
            className="h-4 w-4 accent-cyan-500"
          />
          Include demo data
        </label>
      </div>

      {actionError && <ErrorState message={actionError} />}
      {loading && !data && <Loading label="Loading overview" />}
      {error && <ErrorState message={error} onRetry={reload} />}

      {data && !data.has_data && (
        <Panel>
          <EmptyState
            title="No analyses yet"
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Link to="/traffic" className={btnPrimary}>
                  <Upload className="h-4 w-4" aria-hidden /> Upload a capture
                </Link>
                <button type="button" className={btnSecondary} onClick={loadDemo} disabled={busy}>
                  <FlaskConical className="h-4 w-4" aria-hidden />{' '}
                  {busy ? 'Creating demo...' : 'Load demo data'}
                </button>
              </div>
            }
          >
            Upload a PCAP or PCAPNG file to see traffic statistics and detections. You can also analyze a
            built-in synthetic capture; it is always labeled DEMO.
          </EmptyState>
        </Panel>
      )}

      {data?.has_data && (
        <>
          {data.includes_demo && (
            <Notice tone="warn">
              <DemoBadge /> These figures include {data.demo_analyses} demo (synthetic) analysis
              {data.demo_analyses === 1 ? '' : 'es'}. Untick "Include demo data" to see real captures only.
            </Notice>
          )}

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatCard
              label="Packets analyzed"
              value={formatNumber(data.packets)}
              hint={`${data.analyses} capture(s)`}
            />
            <StatCard label="Bytes analyzed" value={formatBytes(data.bytes)} />
            <StatCard
              label="Source IPs"
              value={formatNumber(data.unique_src_ips)}
              hint="sum of per-capture uniques"
            />
            <StatCard
              label="Destination IPs"
              value={formatNumber(data.unique_dst_ips)}
              hint="sum of per-capture uniques"
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Alerts by severity" className="lg:col-span-1">
              <SeverityBars counts={data.alerts_by_severity} />
            </Panel>
            <Panel
              title={
                <span className="flex items-center gap-2">
                  Traffic over time {data.traffic_over_time?.is_demo && <DemoBadge />}
                </span>
              }
              className="lg:col-span-2"
            >
              {data.traffic_over_time?.series ? (
                <>
                  <p className="mb-2 truncate text-xs text-slate-500">
                    Latest capture: {data.traffic_over_time.filename}
                  </p>
                  <TrafficChart
                    points={data.traffic_over_time.series.points}
                    bucketS={data.traffic_over_time.series.bucket_s}
                  />
                </>
              ) : (
                <p className="py-8 text-center text-sm text-slate-400">No time series available.</p>
              )}
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Protocol distribution">
              <ProtocolChart data={data.protocols} />
            </Panel>
            <Panel title="Top communicating IPs">
              <table className="w-full" aria-label="Top communicating IP addresses">
                <thead>
                  <tr>
                    <th className={th}>IP address</th>
                    <th className={`${th} text-right`}>Packets</th>
                    <th className={`${th} text-right`}>Bytes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-600/40">
                  {data.top_ips.map((ip) => (
                    <tr key={ip.ip}>
                      <td className={`${td} font-mono`}>{ip.ip}</td>
                      <td className={`${td} text-right font-mono`}>{formatNumber(ip.packets)}</td>
                      <td className={`${td} text-right font-mono`}>{formatBytes(ip.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel
              title="Recent alerts"
              action={
                <Link to="/alerts" className="text-xs text-cyan-400 hover:underline">
                  View all
                </Link>
              }
            >
              {data.recent_alerts.length === 0 ? (
                <p className="py-4 text-center text-sm text-slate-400">No alerts.</p>
              ) : (
                <ul className="divide-y divide-ink-600/40">
                  {data.recent_alerts.map((a) => (
                    <li key={a.id} className="flex items-start justify-between gap-3 py-2">
                      <div className="min-w-0">
                        <Link
                          to={`/alerts/${a.id}`}
                          className="block truncate text-sm text-slate-100 hover:text-cyan-300"
                        >
                          {a.title}
                        </Link>
                        <span className="text-xs text-slate-500">{formatTs(a.first_seen)}</span>
                      </div>
                      <div className="flex shrink-0 gap-1.5">
                        <SeverityBadge severity={a.severity} />
                        <StatusBadge status={a.status} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel
              title="Recent analysis sessions"
              action={
                <Link to="/traffic" className="text-xs text-cyan-400 hover:underline">
                  View all
                </Link>
              }
            >
              <ul className="divide-y divide-ink-600/40">
                {data.recent_analyses.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-3 py-2">
                    <div className="min-w-0">
                      <Link
                        to={`/traffic/${a.id}`}
                        className="flex items-center gap-2 truncate text-sm text-slate-100 hover:text-cyan-300"
                      >
                        <span className="truncate">{a.filename}</span> {a.is_demo && <DemoBadge />}
                      </Link>
                      <span className="text-xs text-slate-500">
                        {formatIso(a.created_at)} · {formatNumber(a.packets)} packets
                      </span>
                    </div>
                    <span className="shrink-0 text-xs text-slate-400">{a.alert_total} alerts</span>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}
