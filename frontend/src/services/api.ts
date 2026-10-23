import type {
  Alert,
  AlertDetail,
  AlertStatus,
  Analysis,
  AnalysisListItem,
  AppSettings,
  Overview,
  PacketPage,
  Page,
  RuleInfo,
  Severity,
} from '../types/api'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function describe(detail: unknown, fallback: string): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (d && typeof d === 'object' && 'msg' in d ? String((d as { msg: unknown }).msg) : ''))
      .filter(Boolean)
    if (msgs.length) return msgs.join('; ')
  }
  return fallback
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'Cannot reach the NetSentry API. Is the backend running?')
  }
  if (!res.ok) {
    let detail: unknown
    try {
      detail = (await res.json()).detail
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, describe(detail, `Request failed (${res.status})`))
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export interface TrafficQuery {
  page?: number
  page_size?: number
  q?: string
  proto?: string
  src?: string
  dst?: string
  port?: string
}
export interface AlertQuery {
  page?: number
  page_size?: number
  analysis_id?: string
  severity?: Severity | ''
  status?: AlertStatus | ''
  rule_id?: string
  q?: string
}

export const api = {
  overview: (includeDemo: boolean) => request<Overview>(`/api/overview${qs({ include_demo: includeDemo })}`),
  listAnalyses: (page = 1, page_size = 10) =>
    request<Page & { items: AnalysisListItem[] }>(`/api/analyses${qs({ page, page_size })}`),
  getAnalysis: (id: string) => request<Analysis>(`/api/analyses/${id}`),
  deleteAnalysis: (id: string) => request<void>(`/api/analyses/${id}`, { method: 'DELETE' }),
  createDemo: () => request<Analysis>('/api/analyses/demo', { method: 'POST' }),
  traffic: (id: string, q: TrafficQuery) => request<PacketPage>(`/api/analyses/${id}/traffic${qs({ ...q })}`),
  listAlerts: (q: AlertQuery) => request<Page & { items: Alert[] }>(`/api/alerts${qs({ ...q })}`),
  getAlert: (id: string) => request<AlertDetail>(`/api/alerts/${id}`),
  patchAlert: (id: string, body: { status?: AlertStatus; note?: string }) =>
    request<AlertDetail>(`/api/alerts/${id}`, json('PATCH', body)),
  rules: () => request<RuleInfo[]>('/api/rules'),
  getSettings: () => request<AppSettings>('/api/settings'),
  putSettings: (s: AppSettings) => request<AppSettings>('/api/settings', json('PUT', s)),
}

export const reportUrl = (id: string, kind: 'json' | 'csv' | 'html') => `/api/analyses/${id}/reports/${kind}`

export interface UploadHandle {
  promise: Promise<Analysis>
  abort: () => void
}

/** XHR (not fetch) so we get real upload-progress events. */
export function uploadCapture(
  file: File,
  onProgress: (fraction: number, phase: 'uploading' | 'analyzing') => void,
): UploadHandle {
  const xhr = new XMLHttpRequest()
  const promise = new Promise<Analysis>((resolve, reject) => {
    xhr.open('POST', '/api/analyses')
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total, 'uploading')
    }
    xhr.upload.onload = () => onProgress(1, 'analyzing')
    xhr.onerror = () => reject(new ApiError(0, 'Cannot reach the NetSentry API. Is the backend running?'))
    xhr.onabort = () => reject(new ApiError(0, 'Upload cancelled.'))
    xhr.onload = () => {
      let body: unknown = null
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        /* ignore */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as Analysis)
      else
        reject(
          new ApiError(
            xhr.status,
            describe((body as { detail?: unknown } | null)?.detail, `Upload failed (${xhr.status})`),
          ),
        )
    }
    const form = new FormData()
    form.append('file', file)
    xhr.send(form)
  })
  return { promise, abort: () => xhr.abort() }
}
