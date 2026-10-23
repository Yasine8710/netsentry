import { useState } from 'react'
import { ErrorState, Loading, Notice, Panel, btnPrimary, btnSecondary, inputCls } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import type { AppSettings, RuleInfo } from '../types/api'

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1 text-sm">
      <span className="text-slate-300">{label}</span>
      {children}
      {hint && <span className="block text-xs text-slate-500">{hint}</span>}
    </label>
  )
}

function NumberInput({
  value,
  onChange,
  label,
}: {
  value: number
  onChange: (v: number) => void
  label: string
}) {
  return (
    <input
      aria-label={label}
      type="number"
      value={Number.isNaN(value) ? '' : value}
      onChange={(e) => onChange(e.target.value === '' ? NaN : Number(e.target.value))}
      className={`${inputCls} w-full`}
    />
  )
}

function SettingsForm({
  initial,
  rules,
  onSaved,
}: {
  initial: AppSettings
  rules: RuleInfo[]
  onSaved: (s: AppSettings) => void
}) {
  const [s, setS] = useState<AppSettings>(initial)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const setRule = (id: string, patch: Partial<AppSettings['detection'][string]>) =>
    setS((cur) => ({
      ...cur,
      detection: {
        ...cur.detection,
        [id]: { ...(cur.detection[id] ?? { enabled: true, params: {} }), ...patch },
      },
    }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const res = await api.putSettings(s)
      setS(res)
      onSaved(res)
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save settings')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      {error && <ErrorState message={error} />}
      {saved && (
        <div role="status">
          <Notice>Settings saved. They apply to new analyses.</Notice>
        </div>
      )}

      <Panel title="Limits and retention">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Maximum upload size (MB)" hint="1-500. Larger files are rejected.">
            <NumberInput
              label="Maximum upload size (MB)"
              value={s.max_upload_mb}
              onChange={(v) => setS({ ...s, max_upload_mb: v })}
            />
          </Field>
          <Field
            label="Maximum packets per analysis"
            hint="Parsing stops at this limit and the analysis is flagged."
          >
            <NumberInput
              label="Maximum packets per analysis"
              value={s.max_packets}
              onChange={(v) => setS({ ...s, max_packets: v })}
            />
          </Field>
          <Field
            label="Retention (hours)"
            hint="Analyses older than this are deleted. Uploaded files are deleted right after analysis."
          >
            <NumberInput
              label="Retention (hours)"
              value={s.retention_hours}
              onChange={(v) => setS({ ...s, retention_hours: v })}
            />
          </Field>
          <Field
            label="Packet rows stored per analysis"
            hint="Searchable packet metadata kept per capture (0 disables)."
          >
            <NumberInput
              label="Packet rows stored per analysis"
              value={s.store_packet_rows}
              onChange={(v) => setS({ ...s, store_packet_rows: v })}
            />
          </Field>
        </div>
      </Panel>

      <Panel title="Detection thresholds">
        <p className="mb-4 text-sm text-slate-400">
          Lower thresholds find more activity but raise false positives. Higher thresholds miss smaller
          patterns.
        </p>
        <div className="space-y-5">
          {rules.map((r) => {
            const cfg = s.detection[r.id] ?? { enabled: true, params: {} }
            return (
              <fieldset key={r.id} className="rounded-md border border-ink-600/60 p-4">
                <legend className="px-1 text-sm font-medium text-slate-100">{r.name}</legend>
                <label className="mb-2 flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-cyan-500"
                    checked={cfg.enabled}
                    onChange={(e) => setRule(r.id, { enabled: e.target.checked })}
                  />
                  Enabled
                </label>
                <p className="mb-3 text-xs text-slate-500">{r.false_positive_notes}</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {r.parameters.map((p) => {
                    const label = `${r.name}: ${p.name}`
                    return (
                      <Field
                        key={p.name}
                        label={p.name}
                        hint={`${p.description} Range ${p.minimum}-${p.maximum}, default ${p.default}.`}
                      >
                        <input
                          aria-label={label}
                          type="number"
                          step="any"
                          disabled={!cfg.enabled}
                          value={cfg.params[p.name] ?? p.default}
                          onChange={(e) =>
                            setRule(r.id, { params: { ...cfg.params, [p.name]: Number(e.target.value) } })
                          }
                          className={`${inputCls} w-full disabled:opacity-50`}
                        />
                      </Field>
                    )
                  })}
                </div>
              </fieldset>
            )
          })}
        </div>
      </Panel>

      <Panel title="Interface">
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Density">
            <select
              aria-label="Density"
              value={s.ui.density}
              onChange={(e) =>
                setS({ ...s, ui: { ...s.ui, density: e.target.value as 'comfortable' | 'compact' } })
              }
              className={`${inputCls} w-full`}
            >
              <option value="comfortable">Comfortable</option>
              <option value="compact">Compact</option>
            </select>
          </Field>
          <Field label="Default page size">
            <NumberInput
              label="Default page size"
              value={s.ui.default_page_size}
              onChange={(v) => setS({ ...s, ui: { ...s.ui, default_page_size: v } })}
            />
          </Field>
          <label className="flex items-center gap-2 self-end pb-2 text-sm text-slate-300">
            <input
              type="checkbox"
              className="h-4 w-4 accent-cyan-500"
              checked={s.ui.reduced_motion}
              onChange={(e) => setS({ ...s, ui: { ...s.ui, reduced_motion: e.target.checked } })}
            />
            Reduce motion
          </label>
        </div>
      </Panel>

      <div className="flex gap-3">
        <button type="submit" className={btnPrimary} disabled={saving}>
          {saving ? 'Saving...' : 'Save settings'}
        </button>
        <button type="button" className={btnSecondary} onClick={() => setS(initial)} disabled={saving}>
          Reset changes
        </button>
      </div>
    </form>
  )
}

export default function Settings({ onSaved }: { onSaved?: (s: AppSettings) => void }) {
  const settings = useAsync(() => api.getSettings(), [])
  const rules = useAsync(() => api.rules(), [])
  const err = settings.error ?? rules.error

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Settings</h1>
        <p className="text-sm text-slate-400">Values are validated by the server before they are saved.</p>
      </div>
      {err && <ErrorState message={err} onRetry={() => (settings.reload(), rules.reload())} />}
      {!err && (!settings.data || !rules.data) && <Loading label="Loading settings" />}
      {settings.data && rules.data && (
        <SettingsForm initial={settings.data} rules={rules.data} onSaved={(s) => onSaved?.(s)} />
      )}
    </div>
  )
}
