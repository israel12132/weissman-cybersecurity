import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, cleanup, act, fireEvent } from '@testing-library/react'

const { refetchQueries } = vi.hoisted(() => ({ refetchQueries: vi.fn(() => Promise.resolve()) }))
vi.mock('../lib/queryClient', () => ({ queryClient: { refetchQueries } }))

import MaintenanceProvider from './MaintenanceProvider.jsx'
import MaintenanceOverlay, { isHealthyResponse } from './MaintenanceOverlay.jsx'
import { getMaintenanceCallback, apiUrl } from '../lib/apiBase.js'

const CONTACT = 'weissmancybersecurity@gmail.com'

function health(status, headers = {}) {
  return new Response(status === 200 ? '{"ok":true}' : '{"status":"maintenance"}', {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

const fetchMock = vi.fn()

beforeEach(() => {
  vi.useFakeTimers()
  fetchMock.mockReset()
  refetchQueries.mockClear()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

const overlay = () => screen.queryByTestId('maintenance-overlay')
const advance = (ms) => act(() => vi.advanceTimersByTimeAsync(ms))

describe('isHealthyResponse', () => {
  it('accepts only a genuine, unbranded, non-HTML 200', () => {
    expect(isHealthyResponse(health(200))).toBe(true)
    expect(isHealthyResponse(health(503))).toBe(false)
    expect(isHealthyResponse(health(200, { 'x-weissman-maintenance': '1' }))).toBe(false)
    expect(isHealthyResponse(new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } }))).toBe(
      false,
    )
    expect(isHealthyResponse(null)).toBe(false)
  })
})

describe('MaintenanceProvider + MaintenanceOverlay', () => {
  it('registers the callback while mounted and clears it on unmount', () => {
    const { unmount } = render(
      <MaintenanceProvider>
        <div>app</div>
      </MaintenanceProvider>,
    )
    expect(typeof getMaintenanceCallback()).toBe('function')
    unmount()
    expect(getMaintenanceCallback()).toBeNull()
  })

  it('appears on the callback (idempotent), polls /api/health with the probe contract, and dismisses on 200', async () => {
    render(
      <MaintenanceProvider>
        <div data-testid="app">app</div>
      </MaintenanceProvider>,
    )
    expect(overlay()).toBeNull()

    // Several failing requests signal at once — one overlay, keeps the first signal.
    act(() => {
      getMaintenanceCallback()({ status: 503, retryAfter: 30 })
      getMaintenanceCallback()({ status: 502, retryAfter: 60 })
    })
    const dialog = overlay()
    expect(dialog).not.toBeNull()
    expect(dialog).toHaveAttribute('role', 'alertdialog')
    expect(dialog).toHaveAttribute('aria-labelledby', 'maint-overlay-headline')
    expect(screen.getAllByTestId('maintenance-overlay')).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Command Center is being updated.')
    expect(dialog).toHaveTextContent('Your session resumes automatically once the update completes.')
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByTestId('app')).toBeInTheDocument() // children keep rendering underneath
    expect(dialog).toHaveTextContent('HTTP 503 · Retry-After: 30 s')
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('in 5 s')
    expect(document.activeElement).toBe(dialog)

    // Exactly one contact address, and only the approved one.
    const emails = dialog.textContent.match(/[\w.+-]+@[\w-]+\.[\w.]+/g) || []
    expect(emails).toEqual([CONTACT])
    expect(screen.getByRole('link', { name: CONTACT })).toHaveAttribute('href', `mailto:${CONTACT}`)
    // Register: no outage / error / apology language on the overlay.
    expect(dialog.textContent).not.toMatch(/unavailable|outage|unexpected|error|sorry|apolog|\bdown\b/i)

    // No probe before the first 5 s tick; countdown is live.
    await advance(2000)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('in 3 s')

    // First probe at 5 s: origin still updating → overlay stays, backoff grows (5 → 8 s).
    fetchMock.mockResolvedValueOnce(health(503, { 'x-weissman-maintenance': '1' }))
    await advance(3000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(apiUrl('/api/health'))
    expect(init).toMatchObject({ method: 'GET', cache: 'no-store', credentials: 'omit' })
    expect(init.headers).toMatchObject({ Accept: 'application/json' })
    expect(init.signal).toBeInstanceOf(AbortSignal)
    expect(overlay()).not.toBeNull()
    expect(screen.getByTestId('maintenance-last-checked')).toHaveTextContent(/^\d{2}:\d{2}:\d{2}$/)
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('in 8 s')
    expect(refetchQueries).not.toHaveBeenCalled()

    // A branded 200 must NOT count as restored.
    fetchMock.mockResolvedValueOnce(health(200, { 'x-weissman-maintenance': '1' }))
    await advance(8000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(overlay()).not.toBeNull()
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('in 13 s')

    // Genuine 200 → dismissed, active queries refetched.
    fetchMock.mockResolvedValueOnce(health(200))
    await advance(13000)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(overlay()).toBeNull()
    expect(refetchQueries).toHaveBeenCalledWith({ type: 'active' })
    expect(screen.getByTestId('app')).toBeInTheDocument()

    // No stray timers keep probing after dismissal.
    await advance(60000)
    expect(fetchMock).toHaveBeenCalledTimes(3)

    // A later branded failure re-opens it.
    act(() => getMaintenanceCallback()({ status: 504, retryAfter: 30 }))
    expect(overlay()).not.toBeNull()
    expect(overlay()).toHaveTextContent('HTTP 504')
  })

  it('"Retry now" probes immediately, resets the backoff, and is busy while in flight', async () => {
    const onRestored = vi.fn()
    render(<MaintenanceOverlay status={503} retryAfter={30} onRestored={onRestored} />)
    let resolveProbe
    fetchMock.mockImplementationOnce(() => new Promise((r) => (resolveProbe = r)))
    fireEvent.click(screen.getByRole('button', { name: 'Retry now' }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const btn = screen.getByRole('button', { name: 'Retry now' })
    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('status')).toHaveTextContent('Checking service availability…')
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('now')
    await act(async () => {
      resolveProbe(health(503))
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(btn).toBeEnabled()
    expect(onRestored).not.toHaveBeenCalled()
    // Reset to 5 s then ×1.6 → 8 s for the next automatic check.
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent('in 8 s')

    fetchMock.mockResolvedValueOnce(health(200))
    fireEvent.click(btn)
    await advance(0)
    expect(onRestored).toHaveBeenCalledTimes(1)
  })

  it('a probe that rejects or times out keeps the overlay and keeps polling', async () => {
    const onRestored = vi.fn()
    render(<MaintenanceOverlay onRestored={onRestored} />)
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    await advance(5000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(onRestored).not.toHaveBeenCalled()
    expect(screen.getByRole('status')).toHaveTextContent('re‑checks automatically')
    // Timeout: the probe aborts after 8 s and the cycle continues.
    fetchMock.mockImplementationOnce(
      (_url, { signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        }),
    )
    await advance(8000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    await advance(8000)
    expect(screen.getByTestId('maintenance-next-check')).toHaveTextContent(/in \d+ s/)
    expect(onRestored).not.toHaveBeenCalled()
  })

  it('unmount clears every timer and never probes or restores afterwards', async () => {
    const onRestored = vi.fn()
    const { unmount } = render(<MaintenanceOverlay onRestored={onRestored} />)
    let resolveProbe
    fetchMock.mockImplementationOnce(() => new Promise((r) => (resolveProbe = r)))
    await advance(5000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    unmount()
    await act(async () => {
      resolveProbe(health(200))
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(onRestored).not.toHaveBeenCalled()
    await advance(120000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('caps the backoff at 30 s', async () => {
    render(<MaintenanceOverlay onRestored={() => {}} />)
    const delays = []
    // 5 → 8 → 13 → 21 → 30 → 30
    for (const wait of [5000, 8000, 13000, 21000, 30000, 30000]) {
      fetchMock.mockResolvedValueOnce(health(503))
      await advance(wait)
      delays.push(screen.getByTestId('maintenance-next-check').textContent)
    }
    expect(delays).toEqual(['in 8 s', 'in 13 s', 'in 21 s', 'in 30 s', 'in 30 s', 'in 30 s'])
    expect(fetchMock).toHaveBeenCalledTimes(6)
  })

  it('renders without innerHTML and with the shield mark inline', () => {
    render(<MaintenanceOverlay onRestored={() => {}} />)
    const dialog = overlay()
    expect(dialog.querySelector('svg path[stroke="#020617"]')).not.toBeNull()
    expect(dialog.querySelector('[dangerouslysetinnerhtml]')).toBeNull()
  })
})
