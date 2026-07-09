import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, cleanup } from '@testing-library/react'
import { NotificationProvider, useNotifications } from './NotificationContext'

// Minimal telemetry stub: exposes a way to emit events into the subscriber.
let emit
function StubTelemetryProvider({ children }) {
  return children
}
// Mock useTelemetry to hand back a controllable subscribe().
vi.mock('./TelemetryContext', () => ({
  useTelemetry: () => ({
    subscribe: (fn) => {
      emit = fn
      return () => {
        emit = null
      }
    },
  }),
}))

function Probe() {
  const { notifications, unreadCount, markAllRead, clearAll } = useNotifications()
  return (
    <div>
      <span data-testid="count">{notifications.length}</span>
      <span data-testid="unread">{unreadCount}</span>
      <button onClick={markAllRead}>read</button>
      <button onClick={clearAll}>clear</button>
    </div>
  )
}

function setup() {
  return render(
    <StubTelemetryProvider>
      <NotificationProvider>
        <Probe />
      </NotificationProvider>
    </StubTelemetryProvider>,
  )
}

describe('NotificationProvider', () => {
  beforeEach(() => {
    if (typeof sessionStorage !== 'undefined') sessionStorage.clear()
    emit = null
  })

  afterEach(() => {
    cleanup()
  })

  it('captures error-severity events and counts them unread', () => {
    setup()
    act(() => emit({ severity: 'error', message: 'boom', engine: 'asm' }))
    expect(screen.getByTestId('count').textContent).toBe('1')
    expect(screen.getByTestId('unread').textContent).toBe('1')
  })

  it('captures findings regardless of severity, ignores plain info', () => {
    setup()
    act(() => emit({ severity: 'info', kind: 'finding', message: 'new finding' }))
    act(() => emit({ severity: 'info', kind: 'heartbeat', message: 'ping' }))
    expect(screen.getByTestId('count').textContent).toBe('1')
  })

  it('markAllRead zeroes the unread count but keeps history', () => {
    setup()
    act(() => emit({ severity: 'critical', message: 'sev1' }))
    act(() => screen.getByText('read').click())
    expect(screen.getByTestId('unread').textContent).toBe('0')
    expect(screen.getByTestId('count').textContent).toBe('1')
  })

  it('clearAll empties the inbox', () => {
    setup()
    act(() => emit({ severity: 'high', message: 'sev2' }))
    act(() => screen.getByText('clear').click())
    expect(screen.getByTestId('count').textContent).toBe('0')
  })
})
