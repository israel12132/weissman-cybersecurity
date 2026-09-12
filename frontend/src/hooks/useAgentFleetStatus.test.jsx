import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, cleanup } from '@testing-library/react'

const apiFetch = vi.hoisted(() => vi.fn())
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
  default: (...args) => apiFetch(...args),
}))

import { invalidateAgentFleetCache, useAgentFleetStatus } from './useAgentFleetStatus'

function Probe() {
  const s = useAgentFleetStatus()
  return (
    <div
      data-testid="fleet"
      data-loading={s.loading ? 'true' : 'false'}
      data-unavailable={s.unavailable ? 'true' : 'false'}
      data-online={String(s.onlineCount)}
      data-has-online={s.hasOnlineAgent ? 'true' : 'false'}
    >
      {s.error || 'ok'}
    </div>
  )
}

describe('useAgentFleetStatus', () => {
  beforeEach(() => {
    invalidateAgentFleetCache()
    apiFetch.mockReset()
  })
  afterEach(() => {
    cleanup()
    invalidateAgentFleetCache()
  })

  it('records a live online count from GET /api/agents/status', async () => {
    apiFetch.mockResolvedValue({
      agents: [{ agent_id: 'a1', online: true }],
      online_count: 1,
    })
    render(<Probe />)
    await waitFor(() => expect(screen.getByTestId('fleet').getAttribute('data-loading')).toBe('false'))
    const node = screen.getByTestId('fleet')
    expect(node.getAttribute('data-unavailable')).toBe('false')
    expect(node.getAttribute('data-has-online')).toBe('true')
    expect(node.getAttribute('data-online')).toBe('1')
    expect(apiFetch).toHaveBeenCalledWith('/api/agents/status')
  })

  it('does not cache a transport failure as an empty fleet', async () => {
    apiFetch.mockRejectedValue(Object.assign(new Error('backend exploded'), { status: 503 }))
    render(<Probe />)
    await waitFor(() => expect(screen.getByTestId('fleet').getAttribute('data-loading')).toBe('false'))
    const node = screen.getByTestId('fleet')
    expect(node.getAttribute('data-unavailable')).toBe('true')
    expect(node.getAttribute('data-has-online')).toBe('false')
    expect(node.textContent).toMatch(/backend exploded/)
    expect(apiFetch).toHaveBeenCalledTimes(1)

    apiFetch.mockResolvedValue({
      agents: [{ agent_id: 'a1', online: true }],
      online_count: 1,
    })
    invalidateAgentFleetCache()
    cleanup()
    render(<Probe />)
    await waitFor(() => expect(screen.getByTestId('fleet').getAttribute('data-has-online')).toBe('true'))
    expect(screen.getByTestId('fleet').getAttribute('data-unavailable')).toBe('false')
  })

  it('treats an ok:false JSON body as unavailable, not zero agents', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, agents: [], online_count: 0, detail: 'store down' })
    render(<Probe />)
    await waitFor(() => expect(screen.getByTestId('fleet').getAttribute('data-unavailable')).toBe('true'))
    expect(screen.getByTestId('fleet').getAttribute('data-has-online')).toBe('false')
    expect(screen.getByTestId('fleet').textContent).toMatch(/store down/)
  })
})
