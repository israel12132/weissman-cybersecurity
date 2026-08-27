import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// i18n returns the key so assertions are stable without a provider. initReactI18next/Trans
// are exported too because a transitively-imported child (ProfileMenu) runs src/i18n/index.js.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

// Isolate the page's own loading/empty/error logic from networked/context-bound children.
const apiFetch = vi.fn()
vi.mock('../lib/apiBase', () => ({
  apiFetch: (...args) => apiFetch(...args),
  apiUrl: (p) => p,
}))
// PageShell renders the full app chrome (sidebar, profile menu, telemetry strip) which
// needs app-wide contexts/network. Replace it with a thin layout so we exercise only the
// page's own content (KPIs, loading/empty/error branches).
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
vi.mock('../components/engine/WeissmanListToolbar', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({
    exportCsv: vi.fn(),
    filteredFindings: [],
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))
vi.mock('../components/engine/AgentQueuePanel', () => ({
  __esModule: true,
  default: () => <div data-testid="agent-queue-panel-stub" />,
}))

import AgentManagement from './AgentManagement.jsx'

// Faithful Response-like mock: json() reflects the SAME body as text(), headers.get
// answers content-type, and clone() returns a re-readable copy — matching how the
// unified utils/apiFetch reads success bodies (json()) and error bodies
// (response.clone().json()). The previous mock hardcoded json()->{} with no clone(),
// which only worked with the old r.text()-based reads.
const resp = (over = {}) => {
  const base = { ok: true, status: 200, statusText: '', text: async () => '{}', ...over }
  const build = () => ({
    ...base,
    json: over.json || (async () => JSON.parse((await base.text()) || '{}')),
    headers:
      over.headers || { get: (k) => (String(k).toLowerCase() === 'content-type' ? 'application/json' : null) },
    clone: () => build(),
  })
  return build()
}

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AgentManagement />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AgentManagement', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('shows the empty state when the fleet has no agents', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/agents/status') {
        return Promise.resolve(resp({ text: async () => JSON.stringify({ agents: [] }) }))
      }
      if (url === '/api/clients') return Promise.resolve(resp({ text: async () => '[]' }))
      return Promise.resolve(resp())
    })
    renderPage()
    expect(await screen.findByText('agents.no_agents_title')).toBeInTheDocument()
  })

  it('surfaces an error message when the status endpoint fails', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/agents/status') {
        return Promise.resolve(resp({ ok: false, status: 500, text: async () => JSON.stringify({ detail: 'backend exploded' }) }))
      }
      if (url === '/api/clients') return Promise.resolve(resp({ text: async () => '[]' }))
      return Promise.resolve(resp())
    })
    renderPage()
    expect(await screen.findByText('backend exploded')).toBeInTheDocument()
  })

  it('treats a 404 status endpoint as an empty fleet, not an error', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/agents/status') return Promise.resolve(resp({ status: 404 }))
      if (url === '/api/clients') return Promise.resolve(resp({ text: async () => '[]' }))
      return Promise.resolve(resp())
    })
    renderPage()
    expect(await screen.findByText('agents.no_agents_title')).toBeInTheDocument()
  })
})
