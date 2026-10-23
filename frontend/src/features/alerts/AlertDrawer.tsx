import { X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ErrorState,
  Loading,
  Notice,
  SeverityBadge,
  StatusBadge,
  btnPrimary,
  inputCls,
} from '../../components/ui'
import { useAsync } from '../../hooks/useAsync'
import { api } from '../../services/api'
import { STATUSES, type AlertDetail, type AlertStatus } from '../../types/api'
import { formatIso, formatTs, humanize } from '../../utils/format'

const CONFIDENCE_MEANING =
  'Evidence strength: how clearly the observed pattern exceeds the configured threshold. It is not the probability that the activity is malicious.'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</h3>
      {children}
    </section>
  )
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
      {items.map((i) => (
        <li key={i}>{i}</li>
      ))}
    </ul>
  )
}

function Checklist({ alertId, steps }: { alertId: string; steps: string[] }) {
  const key = `ns.checklist.${alertId}`
  const [done, setDone] = useState<Record<number, boolean>>(() => {
    try {
      return JSON.parse(localStorage.getItem(key) ?? '{}') as Record<number, boolean>
    } catch {
      return {}
    }
  })
  function toggle(i: number) {
    const next = { ...done, [i]: !done[i] }
    setDone(next)
    try {
      localStorage.setItem(key, JSON.stringify(next))
    } catch {
      /* storage unavailable */
    }
  }
  return (
    <ul className="space-y-1.5">
      {steps.map((s, i) => (
        <li key={s}>
          <label className="flex items-start gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={!!done[i]}
              onChange={() => toggle(i)}
              className="mt-1 h-4 w-4 accent-cyan-500"
            />
            <span className={done[i] ? 'text-slate-500 line-through' : ''}>{s}</span>
          </label>
        </li>
      ))}
    </ul>
  )
}

function Timeline({ a }: { a: AlertDetail }) {
  const events: { at: string; text: string }[] = [
    { at: formatTs(a.first_seen), text: 'First observed activity in the capture' },
    { at: formatTs(a.last_seen), text: 'Last observed activity in the capture' },
    { at: formatIso(a.created_at), text: 'Alert created by the detection engine' },
    ...a.updates.map((u) => ({
      at: formatIso(u.created_at),
      text:
        u.kind === 'note'
          ? `Analyst note: ${u.note}`
          : `Status changed: ${humanize(u.old_status ?? '')} -> ${humanize(u.new_status ?? '')}`,
    })),
  ]
  return (
    <ol className="relative space-y-3 border-l border-ink-600 pl-4">
      {events.map((e, i) => (
        <li key={i} className="text-sm">
          <span className="absolute -left-1 mt-1.5 h-2 w-2 rounded-full bg-cyan-500" aria-hidden />
          <div className="font-mono text-xs text-slate-500">{e.at}</div>
          <div className="whitespace-pre-wrap break-words text-slate-300">{e.text}</div>
        </li>
      ))}
    </ol>
  )
}

export default function AlertDrawer({
  id,
  onClose,
  onChanged,
}: {
  id: string
  onClose: () => void
  onChanged: () => void
}) {
  const { data, error, loading, reload } = useAsync(() => api.getAlert(id), [id])
  const [alert, setAlert] = useState<AlertDetail | null>(null)
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const closeRef = useRef<HTMLButtonElement>(null)
  const current = alert && alert.id === id ? alert : data

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  async function save(body: { status?: AlertStatus; note?: string }) {
    setSaving(true)
    setSaveError(null)
    try {
      setAlert(await api.patchAlert(id, body))
      if (body.note) setNote('')
      onChanged()
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Alert details"
        className="relative flex h-full w-full max-w-2xl flex-col overflow-y-auto border-l border-ink-600 bg-ink-900 shadow-2xl"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-ink-600/60 bg-ink-900 px-5 py-4">
          <div className="min-w-0">
            {current ? (
              <>
                <div className="mb-1 flex flex-wrap gap-2">
                  <SeverityBadge severity={current.severity} />
                  <StatusBadge status={current.status} />
                  <span className="text-xs text-slate-400" title={CONFIDENCE_MEANING}>
                    evidence strength: {current.confidence_label} ({current.confidence})
                  </span>
                </div>
                <h2 className="text-base font-semibold text-slate-50">{current.title}</h2>
              </>
            ) : (
              <h2 className="text-base font-semibold text-slate-50">Alert</h2>
            )}
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close alert details"
            className="rounded p-1.5 text-slate-400 hover:bg-ink-700 hover:text-slate-100"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-6 px-5 py-5">
          {loading && !current && <Loading label="Loading alert" />}
          {error && !current && <ErrorState message={error} onRetry={reload} />}
          {current && (
            <>
              <Notice>
                This is a heuristic detection, not proof of an attack. Review the evidence and benign
                explanations before acting.
              </Notice>

              <Section title="What was observed">
                <p className="text-sm text-slate-200">{current.explanation}</p>
                <dl className="grid grid-cols-[110px_1fr] gap-y-1 text-sm">
                  <dt className="text-slate-500">Sources</dt>
                  <dd className="break-all font-mono text-slate-300">
                    {current.src_ips.join(', ') || 'n/a'}
                  </dd>
                  <dt className="text-slate-500">Destinations</dt>
                  <dd className="break-all font-mono text-slate-300">
                    {current.dst_ips.slice(0, 12).join(', ') || 'n/a'}
                  </dd>
                  <dt className="text-slate-500">First seen</dt>
                  <dd className="font-mono text-slate-300">{formatTs(current.first_seen)}</dd>
                  <dt className="text-slate-500">Last seen</dt>
                  <dd className="font-mono text-slate-300">{formatTs(current.last_seen)}</dd>
                  <dt className="text-slate-500">Capture</dt>
                  <dd>
                    <Link to={`/traffic/${current.analysis_id}`} className="text-cyan-300 hover:underline">
                      Open traffic analysis
                    </Link>
                  </dd>
                </dl>
              </Section>

              <Section title="Why it may be suspicious">
                <p className="text-sm text-slate-300">{current.why_suspicious}</p>
              </Section>
              <Section title="Possible benign explanations">
                <Bullets items={current.benign_explanations} />
              </Section>

              <Section title="Supporting evidence">
                <table className="w-full text-sm" aria-label="Evidence">
                  <tbody className="divide-y divide-ink-600/40">
                    {Object.entries(current.evidence).map(([k, v]) => (
                      <tr key={k}>
                        <th scope="row" className="w-1/2 py-1.5 pr-3 text-left font-normal text-slate-400">
                          {humanize(k)}
                        </th>
                        <td className="break-all py-1.5 font-mono text-slate-200">
                          {typeof v === 'string' ? v : JSON.stringify(v)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Section>

              <Section title="Timeline of observed activity">
                <Timeline a={current} />
              </Section>

              <Section title="Investigation checklist">
                <Checklist alertId={current.id} steps={current.recommended_steps} />
              </Section>

              <Section title="Status and analyst notes">
                {saveError && <ErrorState message={saveError} />}
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  Status
                  <select
                    aria-label="Alert status"
                    value={current.status}
                    disabled={saving}
                    onChange={(e) => void save({ status: e.target.value as AlertStatus })}
                    className={inputCls}
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {humanize(s)}
                      </option>
                    ))}
                  </select>
                </label>
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    if (note.trim()) void save({ note: note.trim() })
                  }}
                  className="space-y-2"
                >
                  <label className="block text-sm text-slate-300" htmlFor="analyst-note">
                    Add note
                  </label>
                  <textarea
                    id="analyst-note"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    maxLength={4000}
                    rows={3}
                    className={`${inputCls} w-full`}
                  />
                  <button type="submit" className={btnPrimary} disabled={saving || !note.trim()}>
                    Save note
                  </button>
                </form>
              </Section>

              {current.rule && (
                <Section title={`Detection rule: ${current.rule.name}`}>
                  <p className="text-sm text-slate-300">{current.rule.description}</p>
                  <h4 className="pt-1 text-xs font-medium text-slate-400">Thresholds used</h4>
                  <ul className="space-y-0.5 font-mono text-xs text-slate-300">
                    {Object.entries(current.rule.effective_params).map(([k, v]) => (
                      <li key={k}>
                        {k} = {v}
                      </li>
                    ))}
                  </ul>
                  <h4 className="pt-1 text-xs font-medium text-slate-400">Limitations</h4>
                  <Bullets items={current.rule.limitations} />
                  <p className="text-sm text-slate-400">{current.rule.false_positive_notes}</p>
                  <p className="text-xs text-slate-500">{CONFIDENCE_MEANING}</p>
                </Section>
              )}
            </>
          )}
        </div>
      </aside>
    </div>
  )
}
