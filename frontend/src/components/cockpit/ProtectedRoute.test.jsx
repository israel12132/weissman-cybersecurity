import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-router', () => ({
  Navigate: ({ to }) => <div data-testid="redirect">redirect:{to}</div>,
  useLocation: () => ({ pathname: '/operations' }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))

let mockAuth
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => mockAuth,
}))

import ProtectedRoute from './ProtectedRoute'

beforeEach(() => {
  mockAuth = { isAuthenticated: false, isLoading: false }
})
afterEach(() => cleanup())

describe('ProtectedRoute', () => {
  it('shows verifying state while auth is loading', () => {
    mockAuth = { isAuthenticated: false, isLoading: true }
    render(
      <ProtectedRoute>
        <div>secret</div>
      </ProtectedRoute>,
    )
    expect(screen.getByText('components.cockpitWidgets.protectedRoute.verifying')).toBeInTheDocument()
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
    expect(screen.queryByTestId('redirect')).not.toBeInTheDocument()
  })

  it('sends unauthenticated users to the single Command Center login at /login', () => {
    mockAuth = { isAuthenticated: false, isLoading: false }
    render(
      <ProtectedRoute>
        <div>secret</div>
      </ProtectedRoute>,
    )
    expect(screen.getByTestId('redirect')).toHaveTextContent('redirect:/login')
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
  })

  it('does not send unauthenticated users to a legacy /signin or /auth path', () => {
    mockAuth = { isAuthenticated: false, isLoading: false }
    render(
      <ProtectedRoute>
        <div>secret</div>
      </ProtectedRoute>,
    )
    const dest = screen.getByTestId('redirect').textContent
    expect(dest).not.toMatch(/signin|\/auth\/?$|legacy/i)
    expect(dest).toBe('redirect:/login')
  })

  it('renders children when authenticated', () => {
    mockAuth = { isAuthenticated: true, isLoading: false }
    render(
      <ProtectedRoute>
        <div>secret</div>
      </ProtectedRoute>,
    )
    expect(screen.getByText('secret')).toBeInTheDocument()
    expect(screen.queryByTestId('redirect')).not.toBeInTheDocument()
  })
})
