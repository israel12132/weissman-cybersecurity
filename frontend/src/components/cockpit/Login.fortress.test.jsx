import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { PRODUCTION_ENGINE_COUNT } from '../../lib/platformScale'

vi.mock('react-router', () => ({
  Link: ({ to, children }) => <a href={to}>{children}</a>,
  useNavigate: () => vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key, opts = {}) => {
      if (key === 'auth.trust_engines') return `${opts.engines} engines`
      if (key === 'auth.brand_story') return `Correlate findings across ${opts.engines} attack engines.`
      if (key === 'auth.brand_release') return `${opts.name} · ${opts.release}`
      if (key === 'auth.brand_tagline') return 'Unified offensive security for enterprise teams'
      if (key === 'auth.authenticate') return 'Authenticate'
      if (key === 'common.email') return 'Email'
      if (key === 'common.password') return 'Password'
      return key
    },
  }),
}))

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    login: vi.fn(),
    verifyMfa: vi.fn(),
    isAuthenticated: false,
    isCeo: false,
    isOwner: false,
  }),
}))

vi.mock('../LanguageSwitcher', () => ({
  default: () => <div data-testid="language-switcher" />,
}))

vi.mock('../Logo', () => ({
  default: () => <div data-testid="logo" />,
}))

import Login from './Login'

describe('Login fortress — live cockpit must stay replaced', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn().mockReturnValue({
        matches: false,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    )
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('renders the live cyber backdrop, not a mocked stub', () => {
    const { container } = render(<Login />)
    expect(container.querySelector('.wm-cyber-backdrop')).toBeTruthy()
    expect(container.querySelector('[data-testid="cyber-live-backdrop"]')).toBeTruthy()
    expect(container.querySelector('.wm-cbg-sweep')).toBeTruthy()
    expect(container.querySelector('.wm-cbg-grid')).toBeTruthy()
  })

  it(`locks the live engine count at ${PRODUCTION_ENGINE_COUNT}`, () => {
    render(<Login />)
    expect(PRODUCTION_ENGINE_COUNT).toBe(573)
    expect(screen.getAllByText(`${PRODUCTION_ENGINE_COUNT} engines`).length).toBeGreaterThan(0)
    expect(screen.getByText(`Correlate findings across ${PRODUCTION_ENGINE_COUNT} attack engines.`)).toBeTruthy()
    expect(screen.queryByText('254')).toBeNull()
    expect(screen.queryByText(/254 engines/)).toBeNull()
  })

  it('keeps the real sign-in form (email + password + submit)', () => {
    render(<Login />)
    expect(document.querySelector('input[type="email"]')).toBeTruthy()
    expect(document.querySelector('input[type="password"]')).toBeTruthy()
    expect(screen.getByRole('button', { name: /authenticate/i })).toBeTruthy()
  })
})
