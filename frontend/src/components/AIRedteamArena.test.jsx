import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))
vi.mock('./ui/StandaloneLabShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('./ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import AIRedteamArena from './AIRedteamArena.jsx'

describe('AIRedteamArena', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not treat a store-down clients API as a missing client', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, clients: [], detail: 'store down' })
    render(<AIRedteamArena />)
    expect(await screen.findByTestId('ai-redteam-unavailable')).toBeTruthy()
  })
})
