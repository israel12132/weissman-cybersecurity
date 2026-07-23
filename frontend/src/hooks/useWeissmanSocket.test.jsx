import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useWeissmanSocket } from './useWeissmanSocket.jsx'

// jsdom has no WebSocket. Stub a minimal one that captures the instance so the test
// can drive incoming frames through the hook's onmessage handler.
let lastWs = null
class MockWebSocket {
  static OPEN = 1
  constructor(url) {
    this.url = url
    this.readyState = MockWebSocket.OPEN
    this.onopen = null
    this.onmessage = null
    this.onerror = null
    this.onclose = null
    this.sent = []
    lastWs = this
  }
  send(data) {
    this.sent.push(data)
  }
  close() {
    this.readyState = 3
  }
}

beforeEach(() => {
  lastWs = null
  vi.stubGlobal('WebSocket', MockWebSocket)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function deliver(frame) {
  act(() => {
    lastWs.onmessage({ data: JSON.stringify(frame) })
  })
}

describe('useWeissmanSocket', () => {
  it('connects to the Command Center websocket', () => {
    renderHook(() => useWeissmanSocket())
    expect(lastWs).toBeTruthy()
    expect(lastWs.url).toContain('/ws/command-center')
  })

  it('bumps resyncSignal when the server reports dropped events (backpressure)', () => {
    const { result } = renderHook(() => useWeissmanSocket())
    expect(result.current.resyncSignal).toBe(0)

    deliver({ type: 'resync', kind: 'stream_lagged', dropped: 7, ts: 123 })
    expect(result.current.resyncSignal).toBe(1)

    // A second lag notice bumps again so consumers refetch each time a gap opens.
    deliver({ type: 'resync', dropped: 2 })
    expect(result.current.resyncSignal).toBe(2)
  })

  it('also honors a bare stream_lagged kind (no type field)', () => {
    const { result } = renderHook(() => useWeissmanSocket())
    deliver({ kind: 'stream_lagged', dropped: 1 })
    expect(result.current.resyncSignal).toBe(1)
  })

  it('does not treat a normal telemetry event as a resync', () => {
    const { result } = renderHook(() => useWeissmanSocket())
    deliver({ kind: 'scan_pulse', payload: { message: 'probe', severity: 'info' } })
    expect(result.current.resyncSignal).toBe(0)
    expect(result.current.events.length).toBe(1)
  })
})
