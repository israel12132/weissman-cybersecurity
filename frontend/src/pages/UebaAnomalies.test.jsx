import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k, d) => (typeof d === 'string' ? d : k)
  return {
    useTranslation: () => ({ t, i18n: { language: 'en' } }),
    initReactI18next: { type: '3rdParty', init: () => {} },
    Trans: ({ children }) => children,
  }
})

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, actions, children }) => (
    <div>
      <h1>{title}</h1>
      <div>{actions}</div>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../context/AuthContext', () => ({
  usePermissions: () => ({ hasRole: () => true }),
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({ clients: [{ id: 7, name: 'Acme' }] }),
}))

import UebaAnomalies from './UebaAnomalies.jsx'

function mockOk() {
  apiFetch.mockImplementation((url) => {
    const path = String(url)
    if (path.startsWith('/api/ueba/anomalies')) {
      return Promise.resolve({
        ok: true,
        anomalies: [
          {
            id: 11,
            agent_id: 'agent-1',
            client_id: 7,
            metric_name: 'failed_logins',
            observed: 12,
            baseline_mean: 1,
            baseline_stddev: 0.4,
            z_score: 4.2,
            severity: 'high',
            detail: 'brute-force burst',
            detected_at: '2026-08-27T12:00:00Z',
            status: 'open',
            weighted_score: 8.4,
          },
        ],
      })
    }
    if (path.startsWith('/api/ueba/fleet')) {
      return Promise.resolve({
        ok: true,
        agents: [{ agent_id: 'agent-1', hostname: 'edge-1', is_learning: true, anomalies_24h: 1, last_seen_at: '2026-08-27T12:00:00Z' }],
      })
    }
    if (path.startsWith('/api/ueba/policy')) {
      return Promise.resolve({ policy: { learn_window_days: 14, business_hours_start: 8, business_hours_end: 18 } })
    }
    if (path.startsWith('/api/ueba/whitelist')) {
      return Promise.resolve({ items: [{ id: 3, process_name: 'backupd', reason: 'corp backup' }] })
    }
    return Promise.resolve({})
  })
}

describe('UebaAnomalies', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('shows the empty state when the tenant has no anomalies', async () => {
    apiFetch.mockImplementation((url) => {
      const path = String(url)
      if (path.startsWith('/api/ueba/anomalies')) return Promise.resolve({ ok: true, anomalies: [] })
      if (path.startsWith('/api/ueba/fleet')) return Promise.resolve({ agents: [] })
      if (path.startsWith('/api/ueba/policy')) return Promise.resolve({ policy: { learn_window_days: 7 } })
      if (path.startsWith('/api/ueba/whitelist')) return Promise.resolve({ items: [] })
      return Promise.resolve({})
    })
    render(<UebaAnomalies />)
    expect(await screen.findByText('pages.uebaAnomalies.empty_title')).toBeInTheDocument()
  })

  it('surfaces an error when the anomalies endpoint fails', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).startsWith('/api/ueba/anomalies')) {
        return Promise.reject(new Error('backend exploded'))
      }
      return Promise.resolve({ ok: true, anomalies: [], agents: [], items: [] })
    })
    render(<UebaAnomalies />)
    expect(await screen.findByText('backend exploded')).toBeInTheDocument()
  })

  it('renders live KPIs, fleet learning state, and the process whitelist', async () => {
    mockOk()
    render(<UebaAnomalies />)
    expect(await screen.findByText('failed_logins')).toBeInTheDocument()
    expect(screen.getByText('pages.uebaAnomalies.learning_banner')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'pages.uebaAnomalies.tab_fleet' }))
    expect(await screen.findByText('edge-1')).toBeInTheDocument()
    expect(screen.getByText('pages.uebaAnomalies.learning_yes')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'pages.uebaAnomalies.tab_policy' }))
    expect(await screen.findByText(/backupd/)).toBeInTheDocument()
    expect(screen.getByText('pages.uebaAnomalies.save_policy')).toBeInTheDocument()
  })
})
