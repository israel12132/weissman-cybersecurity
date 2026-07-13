import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, cleanup, act } from '@testing-library/react'

const IDLE_LIMIT_MS = 15 * 60 * 1000
const WARNING_GRACE_MS = 60 * 1000

const logoutSpy = vi.fn()
const warnSpy = vi.fn()
let isAuthenticated = true

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({ isAuthenticated, logout: logoutSpy }),
}))
vi.mock('../ui/Toaster', () => ({
  useToast: () => ({ toast: { warning: warnSpy, success: vi.fn(), error: vi.fn() } }),
}))

import IdleTimeoutWatcher from './IdleTimeoutWatcher'

function advance(ms) {
  act(() => vi.advanceTimersByTime(ms))
}
function fireActivity() {
  act(() => window.dispatchEvent(new KeyboardEvent('keydown')))
}

beforeEach(() => {
  vi.useFakeTimers()
  logoutSpy.mockClear(); warnSpy.mockClear()
  isAuthenticated = true
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('IdleTimeoutWatcher', () => {
  it('warns after the idle limit, then auto-logs-out after the grace period', () => {
    render(<IdleTimeoutWatcher />)
    advance(IDLE_LIMIT_MS - 1)
    expect(warnSpy).not.toHaveBeenCalled()
    advance(2)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    // The warning toast offers a "stay signed in" action.
    expect(warnSpy.mock.calls[0][1]).toMatchObject({ actionLabel: 'session.stay_signed_in' })
    expect(logoutSpy).not.toHaveBeenCalled()
    advance(WARNING_GRACE_MS)
    expect(logoutSpy).toHaveBeenCalledTimes(1)
  })

  it('activity before the limit resets the idle countdown (no premature warning)', () => {
    render(<IdleTimeoutWatcher />)
    advance(5000)
    fireActivity() // resets — deadline moves to now + IDLE_LIMIT_MS
    advance(IDLE_LIMIT_MS - 1)
    expect(warnSpy).not.toHaveBeenCalled()
    advance(2)
    expect(warnSpy).toHaveBeenCalledTimes(1)
  })

  it('activity during the warning window cancels the pending logout', () => {
    render(<IdleTimeoutWatcher />)
    advance(IDLE_LIMIT_MS)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    fireActivity() // in the warning window → immediately cancels + reschedules
    advance(WARNING_GRACE_MS)
    expect(logoutSpy).not.toHaveBeenCalled()
  })

  it('does nothing while unauthenticated', () => {
    isAuthenticated = false
    render(<IdleTimeoutWatcher />)
    advance(IDLE_LIMIT_MS + WARNING_GRACE_MS)
    expect(warnSpy).not.toHaveBeenCalled()
    expect(logoutSpy).not.toHaveBeenCalled()
  })
})
