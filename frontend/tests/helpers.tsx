import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { Alert, AlertDetail, Overview } from '../src/types/api'

type Handler = (url: string, init?: RequestInit) => { status?: number; body?: unknown }

/** Stubs fetch. Keys are "METHOD /path-prefix"; the longest matching key wins. */
export function mockFetch(routes: Record<string, Handler>) {
  const calls: { method: string; url: string; body?: string }[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    calls.push({ method, url, body: init?.body as string | undefined })
    const key = Object.keys(routes)
      .filter((k) => k.startsWith(`${method} `) && url.startsWith(k.slice(method.length + 1)))
      .sort((a, b) => b.length - a.length)[0]
    if (!key) return new Response(JSON.stringify({ detail: `unmocked ${method} ${url}` }), { status: 500 })
    const { status = 200, body } = routes[key](url, init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status })
  })
  vi.stubGlobal('fetch', fn)
  return { calls, fn }
}

export function renderAt(ui: ReactElement, path = '/', routePath = '*') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={routePath} element={ui} />
      </Routes>
    </MemoryRouter>,
  )
}

export const alert = (over: Partial<Alert> = {}): Alert => ({
  id: 'a1',
  analysis_id: 'an1',
  rule_id: 'port_scan',
  severity: 'high',
  title: 'Possible port scan from 1.2.3.4',
  first_seen: 1700000000,
  last_seen: 1700000010,
  src_ips: ['1.2.3.4'],
  dst_ips: ['10.0.0.1'],
  confidence: 0.8,
  confidence_label: 'high',
  status: 'new',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  ...over,
})

export const alertDetail = (over: Partial<AlertDetail> = {}): AlertDetail => ({
  ...alert(),
  evidence: { distinct_ports: 40, threshold: 20 },
  explanation: 'Source sent probes to 40 ports.',
  why_suspicious: 'Typical reconnaissance footprint.',
  benign_explanations: ['Authorized scanner'],
  recommended_steps: ['Check firewall logs', 'Confirm scanner ownership'],
  updates: [],
  rule: {
    id: 'port_scan',
    name: 'Port scan / host sweep',
    description: 'Flags many ports.',
    limitations: ['TCP only'],
    false_positive_notes: 'Scanners look like this.',
    parameters: [],
    effective_params: { min_ports: 20 },
  },
  ...over,
})

export const overview = (over: Partial<Overview> = {}): Overview => ({
  has_data: true,
  includes_demo: false,
  demo_analyses: 0,
  analyses: 1,
  packets: 98765,
  bytes: 2048,
  unique_src_ips: 10,
  unique_dst_ips: 4,
  unique_ips_basis: 'sum_of_per_capture',
  protocols: [{ protocol: 'TCP', packets: 1500, bytes: 2048 }],
  alerts_by_severity: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
  traffic_over_time: null,
  top_ips: [{ ip: '10.0.0.5', packets: 900, bytes: 1000 }],
  recent_alerts: [alert()],
  recent_analyses: [
    {
      id: 'an1',
      filename: 'cap.pcap',
      status: 'completed',
      is_demo: false,
      created_at: '2024-01-01T00:00:00Z',
      packets: 1500,
      bytes: 2048,
      alert_total: 1,
    },
  ],
  ...over,
})
