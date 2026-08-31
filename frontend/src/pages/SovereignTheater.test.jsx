import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k, o) => (o?.n != null ? `${k}:${o.n}` : k)
  return { useTranslation: () => ({ t }) }
})
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))
vi.mock('../lib/sseStream', () => ({
  openSseStream: (_url, opts) => {
    if (typeof opts?.getReconnectUrl === 'function') {
      Promise.resolve(opts.getReconnectUrl()).catch(() => {})
    }
    return { addEventListener: vi.fn(), close: vi.fn() }
  },
}))

import SovereignTheater from './SovereignTheater'

beforeEach(() => {
  apiFetch.mockReset()
  apiFetch.mockImplementation((url) => {
    if (String(url).includes('/session')) {
      return Promise.resolve({
        session_id: 'sess-1',
        messages: [
          { id: 1, role: 'thought', thought_kind: 'observe', content: 'reading live logs' },
          { id: 2, role: 'assistant', content: 'ready' },
        ],
      })
    }
    if (String(url).includes('/windows')) {
      return Promise.resolve({
        windows: [{ id: 9, engine_id: 'osint', phase: 'entered', target: 'https://ex.test', open: true }],
      })
    }
    if (String(url).includes('/logs')) {
      return Promise.resolve({
        events: [{ id: 3, phase: 'entered', engine_id: 'osint', target: 'https://ex.test', ts: 't' }],
      })
    }
    if (String(url).includes('/knowledge')) {
      return Promise.resolve({ knowledge: { production_engine_count: 563, live: true } })
    }
    if (String(url).includes('/memory')) {
      return Promise.resolve({
        memory: [{ id: 1, kind: 'proof', engine_id: 'osint', target: 'https://ex.test', verified: true }],
      })
    }
    if (String(url).includes('/forge')) {
      return Promise.resolve({
        forge: [{ id: 'f1', engine_id: 'osint', title: 'local draft', status: 'local_ok' }],
      })
    }
    if (String(url).includes('/scripts')) {
      return Promise.resolve({
        scripts: [{ id: 2, target: 'https://example.com', method: 'GET', verified: false }],
      })
    }
    if (String(url).includes('/stream-ticket')) {
      return Promise.resolve({
        ok: true,
        ticket: '11111111-1111-1111-1111-111111111111',
        expires_in_sec: 5,
      })
    }
    return Promise.resolve({ ok: true })
  })
})
afterEach(() => cleanup())

describe('SovereignTheater', () => {
  it('loads live session, windows, and knowledge then POSTs owner chat', async () => {
    render(<SovereignTheater />)
    await waitFor(() => expect(screen.getAllByText('osint').length).toBeGreaterThan(0))
    expect(screen.getByText('pages.sovereignTheater.evidence_notice')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/session')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/windows')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/knowledge')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/memory?limit=60')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/forge?limit=30')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/scripts?limit=30')
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/sovereign/operator/stream-ticket',
        expect.objectContaining({ method: 'POST' }),
      ),
    )
    expect(screen.getByText('pages.sovereignTheater.memory')).toBeInTheDocument()
    expect(screen.getByText('pages.sovereignTheater.forge')).toBeInTheDocument()
    expect(screen.getByText('local_ok')).toBeInTheDocument()

    const input = screen.getByPlaceholderText('pages.sovereignTheater.placeholder')
    fireEvent.change(input, { target: { value: 'status of engines' } })
    fireEvent.click(screen.getByText('pages.sovereignTheater.send'))
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/sovereign/operator/chat',
        expect.objectContaining({
          method: 'POST',
          body: expect.objectContaining({ question: 'status of engines' }),
        }),
      ),
    )
  })
})
