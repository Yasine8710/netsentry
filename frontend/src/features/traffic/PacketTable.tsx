import { Search } from 'lucide-react'
import { useState } from 'react'
import {
  EmptyState,
  ErrorState,
  Loading,
  Notice,
  Pagination,
  Panel,
  inputCls,
  td,
  th,
} from '../../components/ui'
import { useAsync, useDebounced } from '../../hooks/useAsync'
import { api } from '../../services/api'
import { formatNumber, formatTs } from '../../utils/format'

const PAGE_SIZE = 25

export default function PacketTable({ analysisId }: { analysisId: string }) {
  const [q, setQ] = useState('')
  const [proto, setProto] = useState('')
  const [src, setSrc] = useState('')
  const [dst, setDst] = useState('')
  const [port, setPort] = useState('')
  const [page, setPage] = useState(1)
  const reset = (set: (v: string) => void, v: string) => {
    set(v)
    setPage(1)
  }
  const filters = useDebounced({ q, src, dst, port }, 350)

  const { data, error, loading, reload } = useAsync(
    () => api.traffic(analysisId, { page, page_size: PAGE_SIZE, proto, ...filters }),
    [analysisId, page, proto, filters],
  )

  return (
    <Panel title="Packet metadata">
      <form
        role="search"
        aria-label="Filter packets"
        className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5"
        onSubmit={(e) => e.preventDefault()}
      >
        <div className="relative lg:col-span-2">
          <Search
            className="pointer-events-none absolute left-2 top-2.5 h-4 w-4 text-slate-500"
            aria-hidden
          />
          <input
            aria-label="Search"
            placeholder="Search IP or DNS name"
            value={q}
            onChange={(e) => reset(setQ, e.target.value)}
            className={`${inputCls} w-full pl-8`}
            maxLength={100}
          />
        </div>
        <select
          aria-label="Protocol"
          value={proto}
          onChange={(e) => reset(setProto, e.target.value)}
          className={inputCls}
        >
          <option value="">All protocols</option>
          {['TCP', 'UDP', 'ICMP', 'OTHER'].map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <input
          aria-label="Source IP"
          placeholder="Source IP"
          value={src}
          onChange={(e) => reset(setSrc, e.target.value)}
          className={inputCls}
          maxLength={45}
        />
        <input
          aria-label="Destination IP"
          placeholder="Destination IP"
          value={dst}
          onChange={(e) => reset(setDst, e.target.value)}
          className={inputCls}
          maxLength={45}
        />
        <input
          aria-label="Port"
          placeholder="Port"
          inputMode="numeric"
          value={port}
          onChange={(e) => reset(setPort, e.target.value.replace(/\D/g, '').slice(0, 5))}
          className={inputCls}
        />
      </form>

      {data?.truncated && (
        <div className="mb-3">
          <Notice tone="warn">
            Showing the first {formatNumber(data.packets_stored)} of {formatNumber(data.packets_total)}{' '}
            packets. Statistics and detections cover the full capture.
          </Notice>
        </div>
      )}

      {loading && !data && <Loading label="Loading packets" />}
      {error && <ErrorState message={error} onRetry={reload} />}
      {data && data.items.length === 0 && !loading && (
        <EmptyState title="No packets match">Adjust or clear the filters.</EmptyState>
      )}
      {data && data.items.length > 0 && (
        <div className={loading ? 'opacity-60 transition-opacity' : ''}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px]" aria-label="Packet metadata">
              <thead>
                <tr>
                  {['#', 'Time', 'Source', 'Destination', 'Proto', 'Len', 'Info'].map((h) => (
                    <th key={h} className={th} scope="col">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-600/40 font-mono text-xs">
                {data.items.map((p) => (
                  <tr key={p.seq}>
                    <td className={td}>{p.seq + 1}</td>
                    <td className={`${td} whitespace-nowrap`}>{formatTs(p.ts).replace(' UTC', '')}</td>
                    <td className={td}>
                      {p.src}
                      {p.sport !== null && <span className="text-slate-500">:{p.sport}</span>}
                    </td>
                    <td className={td}>
                      {p.dst}
                      {p.dport !== null && <span className="text-slate-500">:{p.dport}</span>}
                    </td>
                    <td className={td}>{p.proto}</td>
                    <td className={td}>{p.length}</td>
                    <td className={`${td} max-w-[240px] truncate`} title={p.info ?? ''}>
                      {p.info}
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
  )
}
