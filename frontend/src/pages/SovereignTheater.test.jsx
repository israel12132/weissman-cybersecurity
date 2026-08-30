import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k, o) => (o?.n != null ? `${k}:${o.n}` : k)
  return { useTranslation: () => ({ t }) }
})
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))
vi.mock('../lib/sseStream', () => ({
  openSseStream: () => ({ addEventListener: vi.fn(), close: vi.fn() }),
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
    return Promise.resolve({ ok: true })
  })
})
afterEach(() => cleanup())

describe('SovereignTheater', () => {
  it('loads live session, windows, and knowledge then POSTs owner chat', async () => {
    render(<SovereignTheater />)
    await waitFor(() => expect(screen.getByText('osint')).toBeInTheDocument())
    expect(screen.getByText('pages.sovereignTheater.evidence_notice')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/session')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/windows')
    expect(apiFetch).toHaveBeenCalledWith('/api/sovereign/operator/knowledge')

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
