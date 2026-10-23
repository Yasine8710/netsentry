import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Alerts from '../src/pages/Alerts'
import { alert, alertDetail, mockFetch, renderAt } from './helpers'

const page = (items: unknown[]) => ({ body: { items, total: items.length, page: 1, page_size: 20 } })

test('lists alerts', async () => {
  mockFetch({
    'GET /api/alerts': () =>
      page([alert(), alert({ id: 'a2', title: 'SYN-heavy traffic', severity: 'low' })]),
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts', 'alerts')
  expect(await screen.findByRole('link', { name: /possible port scan/i })).toBeInTheDocument()
  expect(screen.getByText('SYN-heavy traffic')).toBeInTheDocument()
})

test('empty and error states', async () => {
  mockFetch({ 'GET /api/alerts': () => page([]), 'GET /api/rules': () => ({ body: [] }) })
  const { unmount } = renderAt(<Alerts />, '/alerts', 'alerts')
  expect(await screen.findByText('No alerts')).toBeInTheDocument()
  unmount()

  mockFetch({
    'GET /api/alerts': () => ({ status: 500, body: { detail: 'db down' } }),
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts', 'alerts')
  expect(await screen.findByRole('alert')).toHaveTextContent('db down')
})

test('filters are sent to the API', async () => {
  const { calls } = mockFetch({
    'GET /api/alerts': () => page([alert()]),
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts', 'alerts')
  await screen.findByRole('link', { name: /possible port scan/i })
  await userEvent.selectOptions(screen.getByLabelText('Severity'), 'high')
  await waitFor(() => expect(calls.some((c) => c.url.includes('severity=high'))).toBe(true))
})

test('drawer shows evidence, checklist and saves status and notes', async () => {
  let detail = alertDetail()
  const { calls } = mockFetch({
    'GET /api/alerts?': () => page([alert()]),
    'GET /api/alerts/a1': () => ({ body: detail }),
    'PATCH /api/alerts/a1': (_u, init) => {
      const body = JSON.parse(String(init?.body))
      detail = {
        ...detail,
        status: body.status ?? detail.status,
        updates: body.note
          ? [
              ...detail.updates,
              {
                id: 1,
                kind: 'note',
                old_status: null,
                new_status: null,
                note: body.note,
                created_at: '2024-01-02T00:00:00Z',
              },
            ]
          : detail.updates,
      }
      return { body: detail }
    },
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts/a1', 'alerts/:id')
  const dialog = await screen.findByRole('dialog', { name: /alert details/i })
  expect(await within(dialog).findByText('Typical reconnaissance footprint.')).toBeInTheDocument()
  expect(within(dialog).getByText(/not proof of an attack/i)).toBeInTheDocument()
  expect(within(dialog).getByText('distinct ports')).toBeInTheDocument()
  expect(within(dialog).getByText('Authorized scanner')).toBeInTheDocument()
  expect(within(dialog).getByText(/min_ports = 20/)).toBeInTheDocument()

  await userEvent.click(within(dialog).getByLabelText('Check firewall logs'))
  expect(within(dialog).getByLabelText('Check firewall logs')).toBeChecked()

  await userEvent.selectOptions(within(dialog).getByLabelText('Alert status'), 'investigating')
  await waitFor(() =>
    expect(
      calls.some((c) => c.method === 'PATCH' && c.body === JSON.stringify({ status: 'investigating' })),
    ).toBe(true),
  )
  await waitFor(() => expect(within(dialog).getByLabelText('Alert status')).toHaveValue('investigating'))

  const save = within(dialog).getByRole('button', { name: /save note/i })
  expect(save).toBeDisabled()
  await userEvent.type(within(dialog).getByLabelText('Add note'), 'Confirmed scanner')
  await userEvent.click(save)
  expect(await within(dialog).findByText(/Analyst note: Confirmed scanner/)).toBeInTheDocument()
})

test('drawer surfaces save errors', async () => {
  mockFetch({
    'GET /api/alerts?': () => page([alert()]),
    'GET /api/alerts/a1': () => ({ body: alertDetail() }),
    'PATCH /api/alerts/a1': () => ({ status: 422, body: { detail: 'Note too long' } }),
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts/a1', 'alerts/:id')
  const dialog = await screen.findByRole('dialog')
  await userEvent.type(await within(dialog).findByLabelText('Add note'), 'x')
  await userEvent.click(within(dialog).getByRole('button', { name: /save note/i }))
  expect(await within(dialog).findByText('Note too long')).toBeInTheDocument()
})

test('drawer closes with Escape', async () => {
  mockFetch({
    'GET /api/alerts?': () => page([alert()]),
    'GET /api/alerts/a1': () => ({ body: alertDetail() }),
    'GET /api/rules': () => ({ body: [] }),
  })
  renderAt(<Alerts />, '/alerts/a1', 'alerts/:id')
  await screen.findByRole('dialog')
  await userEvent.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
})
