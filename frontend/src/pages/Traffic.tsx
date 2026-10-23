import { Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  DemoBadge,
  EmptyState,
  ErrorState,
  Loading,
  Pagination,
  Panel,
  btnSecondary,
  td,
  th,
} from '../components/ui'
import UploadPanel from '../features/traffic/UploadPanel'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { formatBytes, formatIso, formatNumber } from '../utils/format'

const PAGE_SIZE = 10

export default function Traffic() {
  const [page, setPage] = useState(1)
  const navigate = useNavigate()
  const list = useAsync(() => api.listAnalyses(page, PAGE_SIZE), [page])
  const settings = useAsync(() => api.getSettings(), [])
  const [deleteError, setDeleteError] = useState<string | null>(null)

  async function remove(id: string, name: string) {
    if (!window.confirm(`Delete analysis "${name}" and its alerts?`)) return
    setDeleteError(null)
    try {
      await api.deleteAnalysis(id)
      list.reload()
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : 'Delete failed')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Traffic analysis</h1>
        <p className="text-sm text-slate-400">Upload an offline capture and inspect what it contains.</p>
      </div>

      <UploadPanel maxMb={settings.data?.max_upload_mb} onDone={(a) => navigate(`/traffic/${a.id}`)} />

      <Panel title="Analysis sessions">
        {deleteError && <ErrorState message={deleteError} />}
        {list.loading && !list.data && <Loading label="Loading sessions" />}
        {list.error && <ErrorState message={list.error} onRetry={list.reload} />}
        {list.data && list.data.items.length === 0 && (
          <EmptyState title="No analysis sessions">Upload a capture above to get started.</EmptyState>
        )}
        {list.data && list.data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px]" aria-label="Analysis sessions">
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
                      Bytes
                    </th>
                    <th scope="col" className={`${th} text-right`}>
                      Alerts
                    </th>
                    <th scope="col" className={th}>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-600/40">
                  {list.data.items.map((a) => (
                    <tr key={a.id}>
                      <td className={td}>
                        <Link
                          to={`/traffic/${a.id}`}
                          className="flex items-center gap-2 text-cyan-300 hover:underline"
                        >
                          {a.filename} {a.is_demo && <DemoBadge />}
                        </Link>
                        {a.status !== 'completed' && (
                          <span className="text-xs text-rose-300">{a.status}</span>
                        )}
                      </td>
                      <td className={`${td} whitespace-nowrap text-slate-400`}>{formatIso(a.created_at)}</td>
                      <td className={`${td} text-right font-mono`}>{formatNumber(a.packets)}</td>
                      <td className={`${td} text-right font-mono`}>{formatBytes(a.bytes)}</td>
                      <td className={`${td} text-right font-mono`}>{a.alert_total}</td>
                      <td className={`${td} text-right`}>
                        <button
                          type="button"
                          className={btnSecondary}
                          aria-label={`Delete ${a.filename}`}
                          onClick={() => void remove(a.id, a.filename)}
                        >
                          <Trash2 className="h-4 w-4" aria-hidden />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={setPage} />
          </>
        )}
      </Panel>
    </div>
  )
}
