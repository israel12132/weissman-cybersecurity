import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

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

import EliteHardeningCommandCenter, { eliteControlRows } from './EliteHardeningCommandCenter.jsx'

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EliteHardeningCommandCenter />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('EliteHardeningCommandCenter', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders live controls from GET /api/elite-hardening/status', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      controls_total: 100,
      controls_enforced: 100,
      mitre_attack: 'v19.1',
      live_probes_target: 303,
      controls: [
        { id: 1, section: 1, section_title: 'Offensive Engine Fabric', title: 'Zero-stub', enforced: true, detail: 'dispatch' },
        { id: 4, section: 1, section_title: 'Offensive Engine Fabric', title: 'Evidence doubt', enforced: true, detail: '0.95' },
      ],
    })
    renderPage()
    expect(await screen.findByText('Zero-stub')).toBeInTheDocument()
    expect(screen.getByText('Evidence doubt')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/elite-hardening/status')
  })

  it('surfaces an error when the status endpoint fails', async () => {
    apiFetch.mockRejectedValue(new Error('backend exploded'))
    renderPage()
    expect(await screen.findByText('backend exploded')).toBeInTheDocument()
  })

  it('maps controls to export rows', () => {
    const rows = eliteControlRows([{ id: 91, section_title: 'Ask', title: 'QueryPlan', enforced: true, detail: 'json' }])
    expect(rows[0]).toEqual([91, 'Ask', 'QueryPlan', 'live', 'json'])
  })
})
