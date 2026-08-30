import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

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
  default: ({ title, badge, children }) => (
    <div>
      <h1>{title}</h1>
      {badge && <span>{badge}</span>}
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({ filteredFindings: [] }),
}))

import SoarHitlQueue from './SoarHitlQueue.jsx'

describe('SoarHitlQueue', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    sessionStorage.clear()
  })
  afterEach(cleanup)

  it('renders the empty HITL inbox from the live list API', async () => {
    apiFetch.mockResolvedValue({ items: [], pending_count: 0 })
    render(
      <MemoryRouter>
        <SoarHitlQueue />
      </MemoryRouter>,
    )
    expect(await screen.findByText('pages.soarHitlQueue.empty_title')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/soar/executions?status=pending_hitl')
  })

  it('shows a crown-jewel pending isolate', async () => {
    apiFetch.mockResolvedValue({
      pending_count: 1,
      items: [{
        id: '11111111-1111-1111-1111-111111111111',
        action_kind: 'isolate_host',
        status: 'pending_hitl',
        target_id: 'dc-01.corp',
        crown_jewel_touched: true,
        created_at: '2026-08-27T12:00:00Z',
        blast_radius: { crown_jewel_touched: true },
      }],
    })
    render(
      <MemoryRouter>
        <SoarHitlQueue />
      </MemoryRouter>,
    )
    expect(await screen.findByText('dc-01.corp')).toBeInTheDocument()
    expect(screen.getByText('pages.soarHitlQueue.crown_jewel')).toBeInTheDocument()
    expect(screen.getByText('pages.soarHitlQueue.approve')).toBeInTheDocument()
  })
})
