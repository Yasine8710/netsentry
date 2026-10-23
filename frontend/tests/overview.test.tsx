import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Overview from '../src/pages/Overview'
import { mockFetch, overview, renderAt } from './helpers'

test('shows loading then real data', async () => {
  mockFetch({ 'GET /api/overview': () => ({ body: overview() }) })
  renderAt(<Overview />)
  expect(screen.getByRole('status')).toHaveTextContent(/loading overview/i)
  expect(await screen.findByText('98,765')).toBeInTheDocument()
  expect(screen.getByText('Packets analyzed')).toBeInTheDocument()
  expect(screen.getByText('Possible port scan from 1.2.3.4')).toBeInTheDocument()
  expect(screen.queryByText('DEMO')).not.toBeInTheDocument()
})

test('empty state offers upload and demo', async () => {
  mockFetch({ 'GET /api/overview': () => ({ body: overview({ has_data: false, analyses: 0 }) }) })
  renderAt(<Overview />)
  expect(await screen.findByText('No analyses yet')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: /upload a capture/i })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /load demo data/i })).toBeInTheDocument()
})

test('error state with retry', async () => {
  let fail = true
  mockFetch({
    'GET /api/overview': () => (fail ? { status: 500, body: { detail: 'boom' } } : { body: overview() }),
  })
  renderAt(<Overview />)
  expect(await screen.findByRole('alert')).toHaveTextContent('boom')
  fail = false
  await userEvent.click(screen.getByRole('button', { name: /retry/i }))
  expect(await screen.findByText('98,765')).toBeInTheDocument()
})

test('demo data is clearly flagged and can be excluded', async () => {
  const { calls } = mockFetch({
    'GET /api/overview': (url) =>
      url.includes('include_demo=false')
        ? { body: overview({ has_data: false }) }
        : { body: overview({ includes_demo: true, demo_analyses: 1 }) },
  })
  renderAt(<Overview />)
  expect(await screen.findByText(/include 1 demo \(synthetic\) analysis/i)).toBeInTheDocument()
  await userEvent.click(screen.getByLabelText(/include demo data/i))
  await waitFor(() => expect(calls.some((c) => c.url.includes('include_demo=false'))).toBe(true))
  expect(await screen.findByText('No analyses yet')).toBeInTheDocument()
})

test('loading demo data calls the demo endpoint and reloads', async () => {
  let created = false
  const { calls } = mockFetch({
    'GET /api/overview': () => ({
      body: created ? overview({ includes_demo: true, demo_analyses: 1 }) : overview({ has_data: false }),
    }),
    'POST /api/analyses/demo': () => {
      created = true
      return { status: 201, body: {} }
    },
  })
  renderAt(<Overview />)
  await userEvent.click(await screen.findByRole('button', { name: /load demo data/i }))
  expect(await screen.findByText('98,765')).toBeInTheDocument()
  expect(calls.some((c) => c.method === 'POST' && c.url === '/api/analyses/demo')).toBe(true)
})
