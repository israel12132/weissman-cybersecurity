import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => (typeof d === 'string' ? d : k),
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const { api } = vi.hoisted(() => ({
  api: {
    get: vi.fn(),
    patch: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('../utils/apiFetch', () => ({
  api,
  apiFetch: (...args) => api.get(...args),
  default: (...args) => api.get(...args),
}))

import CrownJewelFlagPanel from './CrownJewelFlagPanel.jsx'

describe('CrownJewelFlagPanel', () => {
  beforeEach(() => {
    api.get.mockReset()
    api.patch.mockReset()
  })
  afterEach(cleanup)

  it('renders nothing without a client', () => {
    const { container } = render(
      <MemoryRouter>
        <CrownJewelFlagPanel clientId={null} />
      </MemoryRouter>,
    )
    expect(container.querySelector('[data-testid="crown-jewel-flag-panel"]')).toBeNull()
    expect(api.get).not.toHaveBeenCalled()
  })

  it('loads live graph nodes and PATCHes crown_jewel', async () => {
    api.get.mockResolvedValue({
      nodes: [
        { id: 41, name: 'dc-01.corp', node_type: 'host', crown_jewel: false, internet_exposed: true },
      ],
    })
    api.patch.mockResolvedValue({ ok: true, graph_dirty: true, crown_jewel: true })
    const onFlagsChanged = vi.fn()

    render(
      <MemoryRouter>
        <CrownJewelFlagPanel clientId={7} onFlagsChanged={onFlagsChanged} />
      </MemoryRouter>,
    )

    expect(await screen.findByText('dc-01.corp')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/risk/graph?client_id=7')

    fireEvent.click(screen.getByText('pages.attackPaths.flag_jewel'))
    await waitFor(() => {
      expect(api.patch).toHaveBeenCalledWith('/api/risk-graph/nodes/41/flags', { crown_jewel: true })
    })
    await waitFor(() => {
      expect(onFlagsChanged).toHaveBeenCalledWith(
        expect.objectContaining({ field: 'crown_jewel', value: true, graphDirty: true }),
      )
    })
  })

  it('toggles internet_exposed on the live node', async () => {
    api.get.mockResolvedValue({
      nodes: [{ id: 9, name: 'edge-vpn', internet_exposed: true, crown_jewel: false }],
    })
    api.patch.mockResolvedValue({ ok: true, graph_dirty: true })

    render(
      <MemoryRouter>
        <CrownJewelFlagPanel clientId={3} />
      </MemoryRouter>,
    )
    expect(await screen.findByText('edge-vpn')).toBeInTheDocument()
    fireEvent.click(screen.getByText('pages.attackPaths.flag_exposed'))
    await waitFor(() => {
      expect(api.patch).toHaveBeenCalledWith('/api/risk-graph/nodes/9/flags', {
        internet_exposed: false,
      })
    })
  })
})
