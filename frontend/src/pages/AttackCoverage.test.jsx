import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))
vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))

import AttackCoverage, { readinessGaps } from './AttackCoverage.jsx'

describe('AttackCoverage', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('readinessGaps drops empty strings', () => {
    expect(readinessGaps(null)).toEqual([])
    expect(readinessGaps({ gaps: ['a', '', '  ', 'b'] })).toEqual(['a', 'b'])
  })

  it('renders attack-readiness gaps from GET /api/attack-coverage', async () => {
    apiFetch.mockResolvedValue({
      framework: 'MITRE ATT&CK',
      tactics: [],
      totals: { techniques_covered: 40, tactics_covered: 12, engine_references: 80 },
      attack_readiness: {
        default_roe: 'safe_proofs',
        threat_emulation_apt_scenarios: 7,
        agent_required_count: 58,
        redteam_cron_engines: ['ai_adversarial_redteam', 'kill_chain', 'autonomous_pentest'],
        gaps: ['Mobile ATT&CK coverage is sparse'],
      },
    })
    render(
      <MemoryRouter>
        <AttackCoverage />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('attack-readiness')).toBeInTheDocument()
    expect(screen.getByText('Mobile ATT&CK coverage is sparse')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/attack-coverage')
  })
})
