import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { sessionHasRole } from '../../lib/roles'

// Keep the guard isolated from router/i18n; drive auth via a mutable stub so we
// can exercise every branch (loading, unauthenticated, denied, allowed).
vi.mock('react-router-dom', () => ({
  Navigate: ({ to }) => <div data-testid="redirect">redirect:{to}</div>,
  Link: ({ to, children }) => <a href={to}>{children}</a>,
  useLocation: () => ({ pathname: '/admin' }),
  useNavigate: () => vi.fn(),
}))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, opts) => (opts ? `${k}:${JSON.stringify(opts)}` : k) }),
}))

let mockAuth
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => mockAuth,
}))

import RequireRole from './RequireRole'

/** Build an auth stub whose hasRole delegates to the REAL role ladder. */
function authFor(role, { isAuthenticated = true, isLoading = false } = {}) {
  const session = { role }
  return {
    isAuthenticated,
    isLoading,
    role,
    logout: vi.fn(),
    hasRole: (min) => sessionHasRole(session, min),
  }
}

beforeEach(() => {
  mockAuth = authFor('admin')
})
afterEach(() => cleanup())

describe('RequireRole guard', () => {
  it('shows the verifying-access state while auth is loading', () => {
    mockAuth = authFor('viewer', { isLoading: true })
    render(<RequireRole min="admin"><div>secret</div></RequireRole>)
    expect(screen.getByText('auth.verifying_access')).toBeInTheDocument()
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
  })

  it('redirects unauthenticated users to /login', () => {
    mockAuth = authFor('admin', { isAuthenticated: false })
    render(<RequireRole min="admin"><div>secret</div></RequireRole>)
    expect(screen.getByTestId('redirect')).toHaveTextContent('redirect:/login')
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
  })

  it('DENIES a lower-privilege authenticated user (the security-bearing branch)', () => {
    mockAuth = authFor('analyst') // analyst < admin on the ladder
    render(<RequireRole min="admin"><div>secret</div></RequireRole>)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('auth.access_denied')).toBeInTheDocument()
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
  })

  it('denies analyst from a ceo-gated route', () => {
    mockAuth = authFor('analyst')
    render(<RequireRole min="ceo"><div>vault</div></RequireRole>)
    expect(screen.getByText('auth.access_denied')).toBeInTheDocument()
    expect(screen.queryByText('vault')).not.toBeInTheDocument()
  })

  it('ALLOWS a user whose role meets the minimum', () => {
    mockAuth = authFor('admin')
    render(<RequireRole min="admin"><div>secret</div></RequireRole>)
    expect(screen.getByText('secret')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('ALLOWS a higher role than the minimum (ceo passes an admin gate)', () => {
    mockAuth = authFor('ceo')
    render(<RequireRole min="admin"><div>secret</div></RequireRole>)
    expect(screen.getByText('secret')).toBeInTheDocument()
  })

  it('superadmin passes every gate', () => {
    mockAuth = authFor('superadmin')
    render(<RequireRole min="ceo"><div>vault</div></RequireRole>)
    expect(screen.getByText('vault')).toBeInTheDocument()
  })
})
