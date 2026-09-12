import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))

import AssetHexGrid from './AssetHexGrid.jsx'

describe('AssetHexGrid', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not claim select-a-client when the clients API is unavailable', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url) === '/api/clients') {
        return Promise.resolve({ ok: false, unavailable: true, clients: [], detail: 'store down' })
      }
      return Promise.resolve({ nodes: [] })
    })
    render(<AssetHexGrid />)
    expect(await screen.findByTestId('asset-hex-clients-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.intelWidgets.assetHexGrid.select_client')).toBeNull()
  })
})
