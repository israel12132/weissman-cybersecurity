import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { UndergroundWarRoom, parseUndergroundPayload, ADVERSARY_PLAYBOOK, sourceChipState } from './DarkWebMonitor.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
}))

vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}))

vi.mock('./PageShell', () => ({ __esModule: true, default: ({ children }) => <div>{children}</div> }))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/EmptyState', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/DataTable', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/FindingDrawer', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/Skeleton', () => ({
  SkeletonTable: () => null,
  SkeletonWidgetGrid: () => null,
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({ exportCsv: () => {} }),
}))
vi.mock('../lib/useJobPoll', () => ({ useJobPoll: () => {} }))
vi.mock('../utils/apiFetch', () => ({ apiFetch: async () => [] }))
vi.mock('../lib/launchEngineScan', () => ({ launchEngineScan: async () => ({ ok: true }) }))
vi.mock('../lib/clientTarget', () => ({ firstClientTarget: () => 'https://example.com' }))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 7, selectedClient: { id: 7, domains: ['example.com'] } }),
}))

describe('underground war room', () => {
  it('parseUndergroundPayload keeps added hits and never invents sources', () => {
    const p = parseUndergroundPayload({
      added: [{ title: 'HIBP verified breach', source: 'hibp' }],
      removed: [],
      hits: [{ source: 'hibp' }],
      current_count: 1,
      previous_count: 0,
      message: 'Baseline snapshot only — next hunt emits the delta.',
    })
    expect(p.added).toHaveLength(1)
    expect(p.current_count).toBe(1)
    expect(p.unavailable).toBe(false)
    expect(parseUndergroundPayload(null).hits).toEqual([])
  })

  it('playbook covers closed-source search plus leak hunter', () => {
    expect(ADVERSARY_PLAYBOOK.some((r) => r.mitre === 'T1597')).toBe(true)
    expect(ADVERSARY_PLAYBOOK.some((r) => r.engines.includes('leak_hunter'))).toBe(true)
  })

  it('sourceChipState distinguishes unreachable from quiet', () => {
    const parsed = parseUndergroundPayload({
      health: [
        { id: 'hibp', ok: true, hit_count: 2 },
        { id: 'urlscan', ok: true, hit_count: 0 },
        { id: 'threatfox', ok: false, hit_count: 0, message: 'HTTP 429' },
      ],
      hits: [{ source: 'hibp' }],
    })
    expect(sourceChipState('hibp', parsed)).toBe('hit')
    expect(sourceChipState('urlscan', parsed)).toBe('quiet')
    expect(sourceChipState('threatfox', parsed)).toBe('failed')
    expect(sourceChipState('urlhaus', parsed)).toBe('unknown')
    expect(sourceChipState('hibp', parseUndergroundPayload({}))).toBe('unknown')
  })

  it('renders delta KPIs and hunt control from live payload', () => {
    render(
      <UndergroundWarRoom
        exposure={{
          message: 'Live snapshot vs previous underground catalog.',
          current_count: 4,
          previous_count: 2,
          added: [{ title: 'new', source: 'hibp' }],
          removed: [],
          hits: [{ source: 'hibp' }, { source: 'threatfox' }],
          sources: ['hibp', 'threatfox'],
          health: [
            { id: 'hibp', ok: true, hit_count: 1 },
            { id: 'threatfox', ok: true, hit_count: 1 },
            { id: 'urlscan', ok: false, message: 'unreachable' },
          ],
        }}
        loading={false}
        hunting={false}
        onHunt={() => {}}
        huntDisabled={false}
        playbookCoverage={{ T1597: true, T1552: false }}
      />,
    )
    expect(screen.getByText('pages.darkWebMonitor.war_title')).toBeTruthy()
    expect(screen.getByText('4')).toBeTruthy()
    expect(screen.getByText('pages.darkWebMonitor.play_proven')).toBeTruthy()
    expect(screen.getByText('pages.darkWebMonitor.hunt')).toBeTruthy()
    expect(screen.getByText('pages.darkWebMonitor.source_failed')).toBeTruthy()
    expect(document.querySelector('li')?.textContent).toMatch(/HIBP/)
  })
})
