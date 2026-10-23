import { Download } from 'lucide-react'
import { useState } from 'react'
import {
  DemoBadge,
  EmptyState,
  ErrorState,
  Loading,
  Notice,
  Pagination,
  Panel,
  td,
  th,
} from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api, reportUrl } from '../services/api'
import { formatIso, formatNumber } from '../utils/format'

const FORMATS = [
  { kind: 'json', label: 'JSON summary' },
  { kind: 'csv', label: 'Alerts CSV' },
  { kind: 'html', label: 'HTML report' },
] as const

export default function Reports() {
  const [page, setPage] = useState(1)
  const { data, error, loading, reload } = useAsync(() => api.listAnalyses(page, 10), [page])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Reports</h1>
        <p className="text-sm text-slate-400">
          Export an analysis summary, alert records or a readable report.
        </p>
      </div>
      <Notice>
        Reports contain capture metadata, statistics, detections and limitations. Packet payloads are never
        included.
      </Notice>
      <Panel title="Available analyses">
        {loading && !data && <Loading label="Loading analyses" />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && (
          <EmptyState title="Nothing to export">Analyze a capture first.</EmptyState>
        )}
        {data && data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px]" aria-label="Reports">
                <thead>
                  <tr>
                    <th scope="col" className={th}>
                      Capture
                    </th>
                    <th scope="col" className={th}>
                      Analyzed
                    </th>
                    <th scope="col" className={`${th} text-right`}>
                      Packets
                    </th>
                    <th scope="col" className={`${th} text-right`}>
                      Alerts
                    </th>
                    <th scope="col" className={th}>
                      Download
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-600/40">
                  {data.items.map((a) => (
                    <tr key={a.id}>
                      <td className={td}>
                        <span className="flex items-center gap-2">
                          {a.filename} {a.is_demo && <DemoBadge />}
                        </span>
                      </td>
                      <td className={`${td} text-slate-400`}>{formatIso(a.created_at)}</td>
                      <td className={`${td} text-right font-mono`}>{formatNumber(a.packets)}</td>
                      <td className={`${td} text-right font-mono`}>{a.alert_total}</td>
                      <td className={td}>
                        <div className="flex flex-wrap gap-3">
                          {FORMATS.map((f) => (
                            <a
                              key={f.kind}
                              href={reportUrl(a.id, f.kind)}
                              {...(f.kind === 'html'
                                ? { target: '_blank', rel: 'noopener noreferrer' }
                                : { download: true })}
                              className="inline-flex items-center gap-1 text-cyan-300 hover:underline"
                              aria-label={`${f.label} for ${a.filename}`}
                            >
                              <Download className="h-3.5 w-3.5" aria-hidden /> {f.label}
                            </a>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={10} total={data.total} onPage={setPage} />
          </>
        )}
      </Panel>
    </div>
  )
}
