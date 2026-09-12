import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}))
vi.mock('./PageShell', () => ({ __esModule: true, default: ({ children }) => <div>{children}</div> }))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanFindingsPanel', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useWeissmanEnginePage', () => ({
  useWeissmanEnginePage: () => ({
    filteredFindings: [],
    counts: {},
    searchQuery: '',
    setSearchQuery: () => {},
    severityFilter: 'all',
    setSeverityFilter: () => {},
    exportCsv: () => {},
    refreshFromHistory: async () => null,
    historyLoading: false,
    lastUpdated: null,
    lastJobId: null,
    setLastUpdated: () => {},
    setLastJobId: () => {},
  }),
  applyHistoryFindings: () => {},
}))
vi.mock('../hooks/useCommandCenterScan', () => ({
  useCommandCenterScan: () => ({ postScan: async () => ({ ok: false, data: {}, status: 0 }) }),
}))
vi.mock('../hooks/useLaunchEngineScan', () => ({ useSyncHubScanParams: () => {} }))
vi.mock('../lib/useJobPoll', () => ({
  useJobPoll: () => {},
  resolveJobFindings: async () => [],
  uiJobStatus: (s) => s,
}))
vi.mock('../lib/clientTarget', () => ({ firstClientTarget: () => '' }))
vi.mock('../components/intel/FirstSeenHitsPanel', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useVisiblePolling', () => ({ useVisiblePolling: () => {} }))
vi.mock('framer-motion', () => ({
  motion: { div: (p) => <div {...p} /> },
  AnimatePresence: ({ children }) => <>{children}</>,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import AttackSurfaceManagement from './AttackSurfaceManagement.jsx'

describe('AttackSurfaceManagement clients honesty', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation((url) => {
      if (url === '/api/clients') {
        return Promise.resolve({ ok: false, unavailable: true, clients: [], detail: 'store down' })
      }
      if (String(url).includes('first-mover/nerve')) {
        return Promise.resolve({ unavailable: true })
      }
      return Promise.resolve({})
    })
  })
  afterEach(cleanup)

  it('does not treat a store-down clients API as an empty tenant', async () => {
    render(<AttackSurfaceManagement />)
    expect(await screen.findByTestId('asm-clients-unavailable')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.clients_unavailable')).toBeTruthy()
  })
})
