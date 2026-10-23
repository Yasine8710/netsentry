import { AlertTriangle, ChevronLeft, ChevronRight, Inbox, Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import type { AlertStatus, Severity } from '../types/api'
import { humanize } from '../utils/format'

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  informational: '#94a3b8',
}

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  informational: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
}

const STATUS_CLASS: Record<AlertStatus, string> = {
  new: 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/30',
  investigating: 'bg-violet-500/15 text-violet-300 ring-violet-500/30',
  resolved: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
  false_positive: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
}

const pill = 'inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${pill} ${SEVERITY_CLASS[severity]}`}>{severity}</span>
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`${pill} ${STATUS_CLASS[status]}`}>{humanize(status)}</span>
}

export function DemoBadge({ label = 'DEMO' }: { label?: string }) {
  return (
    <span
      className="inline-flex items-center rounded bg-amber-400/15 px-1.5 py-0.5 text-[10px] font-bold tracking-wider text-amber-300 ring-1 ring-inset ring-amber-400/40"
      title="Synthetic demo data, not real network traffic"
    >
      {label}
    </span>
  )
}

export function Panel({
  title,
  action,
  children,
  className = '',
}: {
  title?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`min-w-0 rounded-lg border border-ink-600/60 bg-ink-800/70 ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-ink-600/50 px-4 py-3">
          <h2 className="text-sm font-semibold tracking-wide text-slate-200">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function StatCard({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-ink-600/60 bg-ink-800/70 p-4">
      <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
      <div className="mt-1 font-mono text-2xl font-semibold text-slate-50">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  )
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 p-6 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" aria-hidden />
      {label}...
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-4"
    >
      <div className="flex items-center gap-2 text-sm text-rose-200">
        <AlertTriangle className="h-4 w-4" aria-hidden />
        {message}
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className={btnSecondary}>
          Retry
        </button>
      )}
    </div>
  )
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string
  children?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-10 text-center">
      <Inbox className="h-8 w-8 text-slate-600" aria-hidden />
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      {children && <p className="max-w-md text-sm text-slate-400">{children}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export const btnPrimary =
  'inline-flex items-center gap-2 rounded-md bg-cyan-500 px-3 py-1.5 text-sm font-medium text-ink-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50'
export const btnSecondary =
  'inline-flex items-center gap-2 rounded-md border border-ink-600 bg-ink-700/60 px-3 py-1.5 text-sm font-medium text-slate-200 transition-colors hover:bg-ink-600 disabled:cursor-not-allowed disabled:opacity-50'
export const inputCls =
  'rounded-md border border-ink-600 bg-ink-900 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-500'

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number
  pageSize: number
  total: number
  onPage: (p: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  return (
    <nav
      aria-label="Pagination"
      className="flex items-center justify-between gap-3 pt-3 text-sm text-slate-400"
    >
      <span>
        {from.toLocaleString()}-{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className={btnSecondary}
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" aria-hidden />
        </button>
        <span aria-live="polite">
          Page {page} / {pages}
        </span>
        <button
          type="button"
          className={btnSecondary}
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" aria-hidden />
        </button>
      </div>
    </nav>
  )
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warn'; children: ReactNode }) {
  const cls =
    tone === 'warn'
      ? 'border-amber-400/30 bg-amber-400/10 text-amber-200'
      : 'border-cyan-400/30 bg-cyan-400/10 text-cyan-100'
  return <div className={`rounded-md border px-3 py-2 text-sm ${cls}`}>{children}</div>
}

export const th = 'px-3 py-2 text-left text-xs font-medium uppercase tracking-wider text-slate-400'
export const td = 'px-3 py-2 text-sm text-slate-200'
