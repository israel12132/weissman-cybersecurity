import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => {
  const t = (k) => k
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

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 9, name: 'Acme' }],
    selectedClientId: 9,
    setSelectedClientId: () => {},
  }),
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
  useFindingsWorkbench: (rows) => ({
    searchQuery: '',
    setSearchQuery: () => {},
    filteredFindings: rows || [],
    exportCsv: () => {},
  }),
}))

import AdversaryCampaignFabric from './AdversaryCampaignFabric.jsx'

describe('AdversaryCampaignFabric', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('loads campaigns from the live list API for the selected client', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      campaigns: [],
      allowed_goals: ['impact:objective', 'access:foothold'],
    })
    render(
      <MemoryRouter>
        <AdversaryCampaignFabric />
      </MemoryRouter>,
    )
    expect(await screen.findByText('pages.adversaryCampaign.empty_title')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/campaigns?client_id=9')
  })

  it('renders a running campaign WorldState facts', async () => {
    apiFetch.mockImplementation((url) => {
      if (url.startsWith('/api/campaigns?')) {
        return Promise.resolve({
          ok: true,
          campaigns: [{
            id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            client_id: 9,
            goal_fact: 'impact:objective',
            status: 'running',
            asset_key: 'app.example',
          }],
          allowed_goals: ['impact:objective'],
        })
      }
      return Promise.resolve({
        ok: true,
        campaign: {
          id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          client_id: 9,
          status: 'running',
          goal_fact: 'impact:objective',
        },
        world_state: { facts: ['service:web', 'vuln:rce'], evidence: { 'vuln:rce': ['fid-1'] } },
        steps: [{
          id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
          seq: 1,
          technique_id: 'exploit_rce_web',
          technique_name: 'Exploit public-facing app (RCE)',
          mitre: 'T1190',
          engine_id: 'rce_exploit_engine',
          status: 'dispatched',
        }],
        events: [{ kind: 'technique_dispatched', event_version: 1, event_hash: 'abc' }],
        mesh: {
          enabled: true,
          scan_id: 'campaign:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          world_state_on_blackboard: true,
          waves: [['rce_exploit_engine'], ['sqli_advanced']],
          probe_executor: 'engine_dispatch',
          waves_are_preview: true,
        },
        spine: {
          campaign_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          probe_executor: 'engine_dispatch',
          disclose_externally: false,
        },
        council: { hitl_required: true, auto_dispatch: false, queue_path: '/council-queue?campaign_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
      })
    })
    render(
      <MemoryRouter>
        <AdversaryCampaignFabric />
      </MemoryRouter>,
    )
    expect(await screen.findByRole('button', { name: /aaaaaaaa/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /aaaaaaaa/ }))

    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/campaigns/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      )
    })
    expect(await screen.findByText('vuln:rce')).toBeInTheDocument()
    expect(await screen.findByText('service:web')).toBeInTheDocument()
    expect(await screen.findByText('technique_dispatched')).toBeInTheDocument()
    expect(screen.getAllByText('rce_exploit_engine').length).toBeGreaterThan(0)
    expect(screen.getByText('pages.adversaryCampaign.mesh_executor')).toBeInTheDocument()
    expect(screen.getByText('pages.adversaryCampaign.council_hitl_note')).toBeInTheDocument()
    expect(screen.getByText('pages.adversaryCampaign.spine_no_disclose')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'pages.adversaryCampaign.open_jobs' }).getAttribute('href')).toContain(
      'campaign_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    )
    expect(screen.getByRole('link', { name: 'pages.adversaryCampaign.open_council' }).getAttribute('href')).toContain(
      'campaign_id=',
    )
    expect(screen.getByRole('link', { name: 'pages.adversaryCampaign.open_mesh' }).getAttribute('href')).toContain(
      'scan_id=campaign%3Aaaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    )
  })
})
