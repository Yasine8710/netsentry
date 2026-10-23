import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import PacketTable from '../src/features/traffic/PacketTable'
import UploadPanel from '../src/features/traffic/UploadPanel'
import Traffic from '../src/pages/Traffic'
import { formatBytes, formatDuration, formatTs } from '../src/utils/format'
import { mockFetch, renderAt } from './helpers'

const row = (seq: number) => ({
  seq,
  ts: 1700000000 + seq,
  src: '10.0.0.5',
  dst: '10.0.0.6',
  proto: 'TCP',
  sport: 1234,
  dport: 80,
  length: 60,
  tcp_flags: 2,
  info: 'SYN',
})
const packetPage = (n: number, extra = {}) => ({
  body: {
    items: Array.from({ length: n }, (_, i) => row(i)),
    total: n,
    page: 1,
    page_size: 25,
    packets_total: n,
    packets_stored: n,
    truncated: false,
    ...extra,
  },
})

test('packet table paginates and sends filters', async () => {
  const { calls } = mockFetch({ 'GET /api/analyses/an1/traffic': () => packetPage(3) })
  renderAt(<PacketTable analysisId="an1" />)
  expect(await screen.findAllByText('SYN')).toHaveLength(3)
  await userEvent.selectOptions(screen.getByLabelText('Protocol'), 'UDP')
  await userEvent.type(screen.getByLabelText('Search'), '10.0')
  await waitFor(
    () => expect(calls.some((c) => c.url.includes('proto=UDP') && c.url.includes('q=10.0'))).toBe(true),
    { timeout: 2000 },
  )
  expect(calls.every((c) => c.url.includes('page_size=25'))).toBe(true)
})

test('packet table empty, error and truncated states', async () => {
  mockFetch({ 'GET /api/analyses/an1/traffic': () => packetPage(0) })
  const a = renderAt(<PacketTable analysisId="an1" />)
  expect(await screen.findByText('No packets match')).toBeInTheDocument()
  a.unmount()

  mockFetch({
    'GET /api/analyses/an1/traffic': () => ({ status: 404, body: { detail: 'Analysis not found.' } }),
  })
  const b = renderAt(<PacketTable analysisId="an1" />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Analysis not found.')
  b.unmount()

  mockFetch({
    'GET /api/analyses/an1/traffic': () =>
      packetPage(2, { truncated: true, packets_total: 90000, packets_stored: 2 }),
  })
  renderAt(<PacketTable analysisId="an1" />)
  expect(await screen.findByText(/first 2 of 90,000 packets/i)).toBeInTheDocument()
})

test('upload rejects unsupported files client-side without calling the API', async () => {
  const { fn } = mockFetch({})
  renderAt(<UploadPanel onDone={() => undefined} maxMb={50} />)
  const input = document.querySelector('input[type=file]') as HTMLInputElement
  await userEvent.upload(input, new File(['x'], 'notes.txt'), { applyAccept: false })
  expect(await screen.findByRole('alert')).toHaveTextContent(/unsupported file type/i)
  expect(fn).not.toHaveBeenCalled()
})

test('upload rejects oversized files client-side', async () => {
  mockFetch({})
  renderAt(<UploadPanel onDone={() => undefined} maxMb={1} />)
  const input = document.querySelector('input[type=file]') as HTMLInputElement
  const big = new File([new Uint8Array(2 * 1024 * 1024)], 'big.pcap')
  await userEvent.upload(input, big)
  expect(await screen.findByRole('alert')).toHaveTextContent(/limit is 1 MB/i)
})

class FakeXhr {
  static last: FakeXhr
  upload: { onprogress?: (e: unknown) => void; onload?: () => void } = {}
  status = 0
  responseText = ''
  onload?: () => void
  onerror?: () => void
  onabort?: () => void
  open = vi.fn()
  send = vi.fn(() => {
    FakeXhr.last = this
  })
  abort = vi.fn()
}

test('upload shows progress, analyzing state and success', async () => {
  vi.stubGlobal('XMLHttpRequest', FakeXhr)
  const done = vi.fn()
  renderAt(<UploadPanel onDone={done} />)
  const input = document.querySelector('input[type=file]') as HTMLInputElement
  await userEvent.upload(input, new File(['abc'], 'cap.pcap'))
  const x = FakeXhr.last
  x.upload.onprogress?.({ lengthComputable: true, loaded: 50, total: 100 })
  expect(await screen.findByRole('progressbar')).toHaveAttribute('aria-valuenow', '50')
  x.upload.onload?.()
  expect(await screen.findByText(/analyzing cap.pcap/i)).toBeInTheDocument()
  x.status = 201
  x.responseText = JSON.stringify({ id: 'an9', summary: { packets: 42 } })
  x.onload?.()
  expect(await screen.findByText(/analysis complete: 42 packets/i)).toBeInTheDocument()
  expect(done).toHaveBeenCalled()
})

test('upload surfaces server error message', async () => {
  vi.stubGlobal('XMLHttpRequest', FakeXhr)
  renderAt(<UploadPanel onDone={() => undefined} />)
  await userEvent.upload(
    document.querySelector('input[type=file]') as HTMLInputElement,
    new File(['abc'], 'cap.pcap'),
  )
  const x = FakeXhr.last
  x.status = 422
  x.responseText = JSON.stringify({ detail: 'File is not a PCAP or PCAPNG capture (bad magic bytes).' })
  x.onload?.()
  expect(await screen.findByRole('alert')).toHaveTextContent(/bad magic bytes/)
})

test('traffic page: empty sessions list', async () => {
  mockFetch({
    'GET /api/analyses': () => ({ body: { items: [], total: 0, page: 1, page_size: 10 } }),
    'GET /api/settings': () => ({ body: { max_upload_mb: 50 } }),
  })
  renderAt(<Traffic />)
  expect(await screen.findByText('No analysis sessions')).toBeInTheDocument()
  expect(await screen.findByText(/limit: 50 mb/i)).toBeInTheDocument()
})

test('format helpers', () => {
  expect(formatBytes(1536)).toBe('1.5 KB')
  expect(formatBytes(null)).toBe('-')
  expect(formatDuration(0.25)).toBe('250 ms')
  expect(formatDuration(125)).toBe('2m 5s')
  expect(formatTs(0)).toBe('1970-01-01 00:00:00 UTC')
  expect(formatTs(null)).toBe('-')
  expect(formatTs(Number.NaN)).toBe('-')
})
