import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
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
    apiFetch.mockResolvedValue({
      framework: 'MITRE ATT&CK',
      totals: { techniques_covered: 42, tactics_covered: 14, engine_references: 90 },
      tactics: [
        {
          tactic: 'Execution',
          technique_count: 1,
          techniques: [{ id: 'T1059', name: 'Command Interpreter', engines: ['rce_exploit_engine'], engine_count: 1 }],
        },
      ],
      attack_readiness: {
        default_roe: 'safe_proofs',
        threat_emulation_apt_scenarios: 7,
        agent_required_count: 58,
        redteam_cron_engines: ['ai_adversarial_redteam', 'kill_chain', 'autonomous_pentest'],
        gaps: ['ICS ATT&CK Command-and-Control still empty'],
      },
    })
  })
  afterEach(cleanup)

  it('renders the live coverage matrix and honest readiness gaps', async () => {
    render(<AttackCoverage />)
    expect(await screen.findByTestId('attack-readiness')).toBeInTheDocument()
    expect(screen.getByText('ICS ATT&CK Command-and-Control still empty')).toBeInTheDocument()
    expect(screen.getByText('T1059')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/attack-coverage')
  })

  it('readinessGaps drops blanks', () => {
    expect(readinessGaps({ gaps: ['a', '  ', null] })).toEqual(['a'])
    expect(readinessGaps(null)).toEqual([])
  })
})
