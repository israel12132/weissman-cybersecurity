import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, opts) => (opts && typeof opts.count === 'number' ? `${opts.count}T` : k),
    i18n: { language: 'en' },
  }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({ apiFetch: (...a) => apiFetch(...a) }))

import KillChainVisualizer from './KillChainVisualizer.jsx'

afterEach(() => {
  cleanup()
  apiFetch.mockReset()
})

const COVERAGE = {
  framework: 'MITRE ATT&CK',
  tactics: [
    // Deliberately out of kill-chain order to prove the component sorts.
    { tactic: 'Impact', technique_count: 3, techniques: [{ engine_count: 2 }] },
    { tactic: 'Reconnaissance', technique_count: 4, techniques: [{ engine_count: 5 }] },
    { tactic: 'Initial Access', technique_count: 6, techniques: [{ engine_count: 1 }] },
  ],
}

describe('KillChainVisualizer', () => {
  it('reads its data from the live ATT&CK coverage API', async () => {
    apiFetch.mockResolvedValue(COVERAGE)
    render(<KillChainVisualizer />)
    await waitFor(() => expect(screen.getByText('Reconnaissance')).toBeDefined())
    expect(apiFetch).toHaveBeenCalledWith('/api/attack-coverage')
  })

  it('renders tactics in kill-chain order, not API order', async () => {
    apiFetch.mockResolvedValue(COVERAGE)
    render(<KillChainVisualizer />)
    await waitFor(() => expect(screen.getByText('Impact')).toBeDefined())
    const rendered = screen.getAllByRole('listitem').map((li) => li.textContent)
    expect(rendered[0]).toContain('Reconnaissance')
    expect(rendered[1]).toContain('Initial Access')
    expect(rendered[2]).toContain('Impact')
  })

  it('shows each tactic real technique count', async () => {
    apiFetch.mockResolvedValue(COVERAGE)
    render(<KillChainVisualizer />)
    await waitFor(() => expect(screen.getByText('Reconnaissance')).toBeDefined())
    const recon = screen.getAllByRole('listitem')[0]
    expect(recon.textContent).toContain('4T')
  })

  it('surfaces an error state instead of rendering an empty chain', async () => {
    apiFetch.mockRejectedValue(new Error('boom'))
    render(<KillChainVisualizer />)
    await waitFor(() =>
      expect(screen.getByText('components.intelWidgets.killChainVisualizer.error')).toBeDefined(),
    )
    expect(screen.queryAllByRole('listitem')).toHaveLength(0)
  })

  it('renders nothing for a tactic the API does not report', async () => {
    apiFetch.mockResolvedValue({ tactics: [{ tactic: 'Execution', technique_count: 1, techniques: [] }] })
    render(<KillChainVisualizer />)
    await waitFor(() => expect(screen.getByText('Execution')).toBeDefined())
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
    expect(screen.queryByText('Reconnaissance')).toBeNull()
  })
})
