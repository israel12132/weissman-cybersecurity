import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import {
  PLATFORM_RELEASE,
  PLATFORM_RELEASE_NAME,
  PRODUCTION_ENGINE_COUNT,
} from '../../lib/platformScale'

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
  }),
}))

vi.mock('../../hooks/useTenantDirectory', () => ({
  default: () => ({
    status: 'restricted',
    tenants: [],
    defaultSlug: 'default',
    allowCustom: true,
    reload: vi.fn(),
  }),
}))

vi.mock('../CyberLiveBackdrop', () => ({
  default: () => <div data-testid="cyber-live-backdrop" />,
}))

vi.mock('../LanguageSwitcher', () => ({
  default: () => <div data-testid="language-switcher" />,
}))

vi.mock('../Logo', () => ({
  default: () => <div data-testid="logo" />,
}))

import Login from './Login'

describe('Command Center login', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn().mockReturnValue({
        matches: true,
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

  it('shows the current engine fleet and release, never the retired 254 headline', () => {
    render(<Login />)
    expect(screen.getAllByText(`${PRODUCTION_ENGINE_COUNT} engines`).length).toBeGreaterThan(0)
    expect(screen.getByText(`Correlate findings across ${PRODUCTION_ENGINE_COUNT} attack engines.`)).toBeInTheDocument()
    expect(screen.getByText(`${PLATFORM_RELEASE_NAME} · ${PLATFORM_RELEASE}`)).toBeInTheDocument()
    expect(screen.queryByText(/254 engines/)).not.toBeInTheDocument()
    expect(screen.getByTestId('cyber-live-backdrop')).toBeInTheDocument()
    expect(screen.getByLabelText('auth.tenant_slug')).toBeInTheDocument()
  })
})
