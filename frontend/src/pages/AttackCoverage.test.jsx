import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
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
vi.mock('../utils/apiFetch', () => ({
  apiFetch: async () => ({
    framework: 'MITRE ATT&CK',
    tactics: [],
    totals: { techniques_covered: 42, tactics_covered: 12, engine_references: 90 },
    attack_readiness: {
      roe_mode: 'safe_proofs',
      apt_scenario_count: 7,
      redteam_cron_enabled: false,
      redteam_cron_engines: ['kill_chain', 'adversary_path_prover'],
      agent_required_count: 58,
      planner_wired_engines: ['kill_chain', 'adversary_path_prover'],
      thin_tactics: [{ id: 'tactic_thin:Execution', tactic: 'Execution', technique_count: 1 }],
    },
  }),
}))

import AttackCoverage from './AttackCoverage.jsx'

describe('AttackCoverage readiness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the live attack-readiness panel from GET /api/attack-coverage', async () => {
    render(<AttackCoverage />)
    expect(await screen.findByTestId('attack-readiness')).toBeTruthy()
    expect(screen.getByText('pages.attackCoverage.readiness_title')).toBeTruthy()
    expect(screen.getByText(/pages.attackCoverage.thin_tactic/)).toBeTruthy()
    expect(screen.getAllByText(/adversary_path_prover/).length).toBeGreaterThan(0)
  })
})
