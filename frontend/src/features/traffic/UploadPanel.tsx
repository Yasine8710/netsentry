import { CheckCircle2, FileUp, XCircle } from 'lucide-react'
import { useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Panel, btnSecondary } from '../../components/ui'
import { uploadCapture, type UploadHandle } from '../../services/api'
import type { Analysis } from '../../types/api'
import { formatBytes } from '../../utils/format'

type Phase =
  | { kind: 'idle' }
  | { kind: 'uploading'; fraction: number; name: string }
  | { kind: 'analyzing'; name: string }
  | { kind: 'done'; analysis: Analysis }
  | { kind: 'error'; message: string }

const EXT = /\.(pcap|pcapng|cap)$/i

export default function UploadPanel({ onDone, maxMb }: { onDone: (a: Analysis) => void; maxMb?: number }) {
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' })
  const [drag, setDrag] = useState(false)
  const handle = useRef<UploadHandle | null>(null)
  const inputId = useId()

  async function start(file: File) {
    if (!EXT.test(file.name)) {
      setPhase({ kind: 'error', message: 'Unsupported file type. Choose a .pcap, .pcapng or .cap file.' })
      return
    }
    if (maxMb && file.size > maxMb * 1024 * 1024) {
      setPhase({ kind: 'error', message: `File is ${formatBytes(file.size)}; the limit is ${maxMb} MB.` })
      return
    }
    setPhase({ kind: 'uploading', fraction: 0, name: file.name })
    const h = uploadCapture(file, (fraction, p) =>
      setPhase(
        p === 'analyzing'
          ? { kind: 'analyzing', name: file.name }
          : { kind: 'uploading', fraction, name: file.name },
      ),
    )
    handle.current = h
    try {
      const analysis = await h.promise
      setPhase({ kind: 'done', analysis })
      onDone(analysis)
    } catch (e) {
      setPhase({ kind: 'error', message: e instanceof Error ? e.message : 'Upload failed' })
    } finally {
      handle.current = null
    }
  }

  const busy = phase.kind === 'uploading' || phase.kind === 'analyzing'

  return (
    <Panel title="Analyze a capture">
      <div
        onDragOver={(e) => {
          e.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDrag(false)
          const f = e.dataTransfer.files[0]
          if (f && !busy) void start(f)
        }}
        className={`flex flex-col items-center gap-3 rounded-lg border border-dashed p-6 text-center transition-colors ${
          drag ? 'border-cyan-400 bg-cyan-400/5' : 'border-ink-600'
        }`}
      >
        <FileUp className="h-7 w-7 text-slate-500" aria-hidden />
        <p className="text-sm text-slate-300">Drop a PCAP/PCAPNG file here, or choose one.</p>
        <label
          htmlFor={inputId}
          className={`${btnSecondary} cursor-pointer ${busy ? 'pointer-events-none opacity-50' : ''}`}
        >
          Choose file
        </label>
        <input
          id={inputId}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="sr-only"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) void start(f)
            e.target.value = ''
          }}
        />
        <p className="text-xs text-slate-500">
          Files are analyzed on the server and deleted right after. Only packet metadata is kept.
          {maxMb ? ` Limit: ${maxMb} MB.` : ''}
        </p>
      </div>

      <div className="mt-4 min-h-6" aria-live="polite">
        {phase.kind === 'uploading' && (
          <div role="status">
            <div className="mb-1 flex justify-between text-xs text-slate-400">
              <span className="truncate">Uploading {phase.name}</span>
              <span>{Math.round(phase.fraction * 100)}%</span>
            </div>
            <div
              role="progressbar"
              aria-label="Upload progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(phase.fraction * 100)}
              className="h-2 overflow-hidden rounded bg-ink-700"
            >
              <div
                className="h-full bg-cyan-500 transition-[width]"
                style={{ width: `${phase.fraction * 100}%` }}
              />
            </div>
            <button
              type="button"
              className="mt-2 text-xs text-slate-400 underline"
              onClick={() => handle.current?.abort()}
            >
              Cancel
            </button>
          </div>
        )}
        {phase.kind === 'analyzing' && (
          <div role="status" className="text-sm text-slate-300">
            Analyzing {phase.name}... parsing packets and running detection rules.
          </div>
        )}
        {phase.kind === 'done' && (
          <div role="status" className="flex flex-wrap items-center gap-2 text-sm text-emerald-300">
            <CheckCircle2 className="h-4 w-4" aria-hidden />
            Analysis complete: {phase.analysis.summary?.packets.toLocaleString() ?? 0} packets.
            <Link to={`/traffic/${phase.analysis.id}`} className="text-cyan-300 underline">
              Open results
            </Link>
          </div>
        )}
        {phase.kind === 'error' && (
          <div role="alert" className="flex items-start gap-2 text-sm text-rose-300">
            <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            {phase.message}
          </div>
        )}
      </div>
    </Panel>
  )
}
