import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k, o) => (o?.jobId ? `${k}:${o.jobId}` : k)
  return { useTranslation: () => ({ t }) }
})
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../lib/apiBase', () => ({ apiFetch }))

import CeoSovereignLab from './CeoSovereignLab'

const BUFFER = [
  { id: 'buf-1', target_fingerprint: 'nginx/1.25 · php8', status: 'shadow_ready', updated_at: '2026-07-21' },
  { id: 'buf-2', target_fingerprint: 'apache · wp6', status: 'queued', updated_at: '2026-07-20' },
]

beforeEach(() => apiFetch.mockReset())
afterEach(() => cleanup())

describe('CeoSovereignLab → DataTable', () => {
  it('renders buffer rows and fires the preflight trigger POST from the action cell', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/trigger')) return Promise.resolve({ ok: true, json: () => Promise.resolve({ job_id: 'job-42' }) })
      return Promise.resolve({ ok: true, json: () => Promise.resolve(BUFFER) })
    })
    render(<CeoSovereignLab />)

    await waitFor(() => expect(screen.getByText('nginx/1.25 · php8')).toBeInTheDocument())
    const rows = document.querySelectorAll('table tbody tr')
    expect(rows.length).toBe(BUFFER.length)

    // The action column renders trigger buttons; clicking one POSTs to /trigger.
    const triggerButtons = screen.getAllByText('components.ceo.sovereignLab.triggerPreflight')
    expect(triggerButtons.length).toBe(BUFFER.length)
    fireEvent.click(triggerButtons[0])
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith('/api/ceo/sovereign/trigger', expect.objectContaining({ method: 'POST' })),
    )
  })
})
