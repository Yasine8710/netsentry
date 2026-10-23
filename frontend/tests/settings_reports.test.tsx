import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Reports from '../src/pages/Reports'
import Settings from '../src/pages/Settings'
import type { AppSettings } from '../src/types/api'
import { mockFetch, renderAt } from './helpers'

const settings: AppSettings = {
  max_upload_mb: 50,
  max_packets: 500000,
  retention_hours: 720,
  store_packet_rows: 50000,
  detection: {},
  ui: { density: 'comfortable', reduced_motion: false, default_page_size: 25 },
}
const rules = [
  {
    id: 'port_scan',
    name: 'Port scan / host sweep',
    description: 'd',
    limitations: ['l'],
    false_positive_notes: 'Scanners look like this.',
    parameters: [
      { name: 'min_ports', default: 20, minimum: 2, maximum: 65535, description: 'Distinct ports.' },
    ],
    effective_params: { min_ports: 20 },
  },
]

test('settings: loads and saves validated values', async () => {
  const saved = vi.fn()
  const { calls } = mockFetch({
    'GET /api/settings': () => ({ body: settings }),
    'GET /api/rules': () => ({ body: rules }),
    'PUT /api/settings': (_u, init) => ({ body: JSON.parse(String(init?.body)) }),
  })
  renderAt(<Settings onSaved={saved} />)
  const limit = await screen.findByLabelText('Maximum upload size (MB)')
  expect(limit).toHaveValue(50)
  await userEvent.clear(limit)
  await userEvent.type(limit, '100')
  const ports = screen.getByLabelText('Port scan / host sweep: min_ports')
  await userEvent.clear(ports)
  await userEvent.type(ports, '30')
  await userEvent.click(screen.getByRole('button', { name: /save settings/i }))
  expect(await screen.findByText(/settings saved/i)).toBeInTheDocument()
  const put = calls.find((c) => c.method === 'PUT')!
  const body = JSON.parse(put.body!)
  expect(body.max_upload_mb).toBe(100)
  expect(body.detection.port_scan.params.min_ports).toBe(30)
  expect(saved).toHaveBeenCalled()
})

test('settings: shows backend validation error', async () => {
  mockFetch({
    'GET /api/settings': () => ({ body: settings }),
    'GET /api/rules': () => ({ body: rules }),
    'PUT /api/settings': () => ({ status: 422, body: { detail: 'min_ports: must be between 2 and 65535' } }),
  })
  renderAt(<Settings />)
  await userEvent.click(await screen.findByRole('button', { name: /save settings/i }))
  expect(await screen.findByRole('alert')).toHaveTextContent('must be between 2 and 65535')
})

test('settings: load error', async () => {
  mockFetch({
    'GET /api/settings': () => ({ status: 500, body: { detail: 'nope' } }),
    'GET /api/rules': () => ({ body: rules }),
  })
  renderAt(<Settings />)
  expect(await screen.findByRole('alert')).toHaveTextContent('nope')
})

test('reports: lists download links, HTML opens safely in a new tab', async () => {
  mockFetch({
    'GET /api/analyses': () => ({
      body: {
        items: [
          {
            id: 'an1',
            filename: 'cap.pcap',
            status: 'completed',
            is_demo: true,
            created_at: '2024-01-01T00:00:00Z',
            packets: 10,
            bytes: 100,
            alert_total: 2,
          },
        ],
        total: 1,
        page: 1,
        page_size: 10,
      },
    }),
  })
  renderAt(<Reports />)
  const html = await screen.findByRole('link', { name: /html report for cap.pcap/i })
  expect(html).toHaveAttribute('href', '/api/analyses/an1/reports/html')
  expect(html).toHaveAttribute('rel', 'noopener noreferrer')
  expect(screen.getByRole('link', { name: /alerts csv/i })).toHaveAttribute(
    'href',
    '/api/analyses/an1/reports/csv',
  )
  expect(screen.getByText('DEMO')).toBeInTheDocument()
  expect(screen.getByText(/payloads are never included/i)).toBeInTheDocument()
})

test('reports: empty state', async () => {
  mockFetch({ 'GET /api/analyses': () => ({ body: { items: [], total: 0, page: 1, page_size: 10 } }) })
  renderAt(<Reports />)
  expect(await screen.findByText('Nothing to export')).toBeInTheDocument()
})
