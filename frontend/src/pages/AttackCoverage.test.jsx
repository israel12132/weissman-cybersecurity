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
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title, body }) => (
    <div>
      <h2>{title}</h2>
      <p>{body}</p>
    </div>
  ),
}))
vi.mock('../components/ui/EvidenceNotice', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/ui/ExecutiveWidget', () => ({
  __esModule: true,
  default: ({ label, value }) => (
    <div>
      {label}: {value}
    </div>
  ),
}))
vi.mock('../components/ui/Skeleton', () => ({
  SkeletonWidgetGrid: () => null,
  SkeletonCard: () => null,
}))

import AttackCoverage from './AttackCoverage.jsx'

const COVERAGE = {
  framework: 'MITRE ATT&CK',
  totals: { techniques_covered: 42, tactics_covered: 12, engine_references: 90 },
  tactics: [
    {
      tactic: 'Initial Access',
      techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', engines: ['sqli_advanced'] }],
    },
  ],
  readiness: {
    roe_default: 'safe_proofs',
    weaponized_exploits: false,
    scheduled_redteam: 'off_by_default',
    host_resident: 'ROP/heap/JIT/COM/PPID are inventory + remote surface, not exploit execution',
    gaps: [
      { id: 'ics_c2_privesc', label: 'ICS C2 / Privilege Escalation', note: 'MQTT/IEC-104 live HTTP only' },
    ],
  },
}

describe('AttackCoverage', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders live ATT&CK coverage and the readiness panel from GET /api/attack-coverage', async () => {
    apiFetch.mockResolvedValue(COVERAGE)
    render(
      <MemoryRouter>
        <AttackCoverage />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('attack-coverage-readiness')).toBeInTheDocument()
    expect(screen.getByText('pages.attackCoverage.readiness_title')).toBeInTheDocument()
    expect(screen.getByText(/safe_proofs/)).toBeInTheDocument()
    expect(screen.getByTestId('attack-coverage-weaponized')).toHaveTextContent(
      'pages.attackCoverage.weaponized_no',
    )
    expect(screen.getByText('ICS C2 / Privilege Escalation')).toBeInTheDocument()
    expect(screen.getByText('T1190')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/attack-coverage')
  })
})
