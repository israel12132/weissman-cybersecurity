import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../ui/GeoWorldMap', () => ({
  __esModule: true,
  default: ({ children }) => <div data-testid="geo-map">{children}</div>,
  GeoMarker: ({ children }) => <div>{children}</div>,
}))
vi.mock('../ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import GlobalEdgeSwarmMap from './GlobalEdgeSwarmMap.jsx'

describe('GlobalEdgeSwarmMap', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    vi.stubGlobal('setInterval', () => 0)
    vi.stubGlobal('clearInterval', () => {})
  })
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('does not paint no-nodes theater when the swarm API is unavailable', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/api/edge-swarm/nodes')) {
        return Promise.resolve({ ok: false, unavailable: true, nodes: [], detail: 'store down' })
      }
      return Promise.resolve({ crate: 'fuzz_core' })
    })
    render(<GlobalEdgeSwarmMap />)
    expect(await screen.findByTestId('edge-swarm-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitWidgets.globalEdgeSwarmMap.noNodes')).toBeNull()
  })
})
