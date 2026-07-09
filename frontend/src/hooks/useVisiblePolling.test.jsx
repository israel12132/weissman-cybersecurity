import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import { useVisiblePolling } from './useVisiblePolling'

function Harness({ fn, intervalMs, paused }) {
  useVisiblePolling(fn, intervalMs, { paused })
  return null
}

describe('useVisiblePolling', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    // default: visible
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => false })
  })
  afterEach(() => {
    cleanup()
    vi.useRealTimers()
  })

  it('invokes fn once per interval while visible', () => {
    const fn = vi.fn()
    render(<Harness fn={fn} intervalMs={1000} paused={false} />)
    expect(fn).not.toHaveBeenCalled()
    vi.advanceTimersByTime(3000)
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it('skips ticks while the document is hidden', () => {
    const fn = vi.fn()
    let hidden = false
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden })
    render(<Harness fn={fn} intervalMs={1000} paused={false} />)
    vi.advanceTimersByTime(1000) // visible → fires
    hidden = true
    vi.advanceTimersByTime(2000) // hidden → skipped
    hidden = false
    vi.advanceTimersByTime(1000) // visible → fires
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('does not run while paused, and never starts a timer when paused', () => {
    const fn = vi.fn()
    render(<Harness fn={fn} intervalMs={1000} paused />)
    vi.advanceTimersByTime(5000)
    expect(fn).not.toHaveBeenCalled()
  })

  it('disables the timer for non-positive intervals', () => {
    const fn = vi.fn()
    render(<Harness fn={fn} intervalMs={0} paused={false} />)
    vi.advanceTimersByTime(5000)
    expect(fn).not.toHaveBeenCalled()
  })

  it('uses the latest fn without restarting the interval', () => {
    const first = vi.fn()
    const second = vi.fn()
    const { rerender } = render(<Harness fn={first} intervalMs={1000} paused={false} />)
    vi.advanceTimersByTime(1000)
    expect(first).toHaveBeenCalledTimes(1)
    rerender(<Harness fn={second} intervalMs={1000} paused={false} />)
    vi.advanceTimersByTime(1000)
    expect(second).toHaveBeenCalledTimes(1)
    expect(first).toHaveBeenCalledTimes(1) // not called again
  })

  it('stops firing after unmount', () => {
    const fn = vi.fn()
    const { unmount } = render(<Harness fn={fn} intervalMs={1000} paused={false} />)
    vi.advanceTimersByTime(1000)
    unmount()
    vi.advanceTimersByTime(3000)
    expect(fn).toHaveBeenCalledTimes(1)
  })
})
