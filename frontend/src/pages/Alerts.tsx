import { useCallback, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  EmptyState,
  ErrorState,
  Loading,
  Pagination,
  Panel,
  SeverityBadge,
  StatusBadge,
  inputCls,
  td,
  th,
} from '../components/ui'
import AlertDrawer from '../features/alerts/AlertDrawer'
import { useAsync, useDebounced } from '../hooks/useAsync'
import { api } from '../services/api'
import { SEVERITIES, STATUSES, type AlertStatus, type Severity } from '../types/api'
import { formatTs, humanize } from '../utils/format'

const PAGE_SIZE = 20

export default function Alerts() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const analysisId = params.get('analysis_id') ?? ''
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<AlertStatus | ''>('')
  const [rule, setRule] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const dq = useDebounced(q, 350)

  const rules = useAsync(() => api.rules(), [])
  const { data, error, loading, reload } = useAsync(
    () =>
      api.listAlerts({
        page,
        page_size: PAGE_SIZE,
        severity,
        status,
        rule_id: rule,
        q: dq,
        analysis_id: analysisId,
      }),
    [page, severity, status, rule, dq, analysisId],
  )
  const close = useCallback(
    () => navigate(analysisId ? `/alerts?analysis_id=${analysisId}` : '/alerts'),
    [navigate, analysisId],
  )

  const filter =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v)
      setPage(1)
    }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Threat detection</h1>
        <p className="text-sm text-slate-400">
          Heuristic alerts from the rule engine. They are leads for investigation, not confirmed attacks.
          {analysisId && (
            <>
              {' '}
              Filtered to one capture.{' '}
              <Link to="/alerts" className="text-cyan-300 hover:underline">
                Clear
              </Link>
            </>
          )}
        </p>
      </div>

      <Panel>
        <form
          role="search"
          aria-label="Filter alerts"
          onSubmit={(e) => e.preventDefault()}
          className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4"
        >
          <input
            aria-label="Search alerts"
            placeholder="Search title"
            value={q}
            onChange={(e) => filter(setQ)(e.target.value)}
            className={inputCls}
            maxLength={100}
          />
          <select
            aria-label="Severity"
            value={severity}
            onChange={(e) => filter(setSeverity)(e.target.value as Severity | '')}
            className={inputCls}
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            aria-label="Status"
            value={status}
            onChange={(e) => filter(setStatus)(e.target.value as AlertStatus | '')}
            className={inputCls}
          >
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {humanize(s)}
              </option>
            ))}
          </select>
          <select
            aria-label="Rule"
            value={rule}
            onChange={(e) => filter(setRule)(e.target.value)}
            className={inputCls}
          >
            <option value="">All rules</option>
            {(rules.data ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </form>

        {loading && !data && <Loading label="Loading alerts" />}
        {error && <ErrorState message={error} onRetry={reload} />}
        {data && data.items.length === 0 && !loading && (
          <EmptyState title="No alerts">
            No alerts match these filters. Analyze a capture or relax the filters.
          </EmptyState>
        )}
        {data && data.items.length > 0 && (
          <div className={loading ? 'opacity-60 transition-opacity' : ''}>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px]" aria-label="Alerts">
                <thead>
                  <tr>
                    {['Severity', 'Alert', 'Rule', 'First seen', 'Evidence', 'Status'].map((h) => (
                      <th key={h} scope="col" className={th}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-600/40">
                  {data.items.map((a) => (
                    <tr key={a.id} className="hover:bg-ink-700/30">
                      <td className={td}>
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td className={`${td} max-w-[320px]`}>
                        <Link
                          to={`/alerts/${a.id}${analysisId ? `?analysis_id=${analysisId}` : ''}`}
                          className="text-cyan-300 hover:underline"
                        >
                          {a.title}
                        </Link>
                      </td>
                      <td className={`${td} font-mono text-xs`}>{a.rule_id}</td>
                      <td className={`${td} whitespace-nowrap font-mono text-xs`}>
                        {formatTs(a.first_seen)}
                      </td>
                      <td className={`${td} capitalize`}>{a.confidence_label}</td>
                      <td className={td}>
                        <StatusBadge status={a.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
          </div>
        )}
      </Panel>

      {id && <AlertDrawer id={id} onClose={close} onChanged={reload} />}
    </div>
  )
}
