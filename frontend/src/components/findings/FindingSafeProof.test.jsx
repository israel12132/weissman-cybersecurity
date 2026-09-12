import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import FindingSafeProof from './FindingSafeProof.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

describe('FindingSafeProof', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('loads artifacts and posts a live proof without inventing evidence', async () => {
    apiFetch.mockImplementation((url, opts) => {
      if (opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          invented: false,
          proof_status: 'proven',
          reason: 'OAST hit correlated to this finding',
          artifacts: [{ id: 9, adapter: 'oast', kind: 'oast_hit', evidence: { hit_id: 7 } }],
        })
      }
      return Promise.resolve({
        ok: true,
        proof_status: 'observed',
        artifacts: [],
      })
    })
    const onProofComplete = vi.fn()
    render(
      <FindingSafeProof
        finding={{ raw_id: 42, title: 'SSRF', proof_status: 'observed' }}
        onProofComplete={onProofComplete}
      />,
    )
    expect(await screen.findByText('findings.proof.no_artifacts')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'findings.proof.run' }))
    await waitFor(() => {
      expect(onProofComplete).toHaveBeenCalled()
    })
    expect(apiFetch).toHaveBeenCalledWith('/api/findings/42/proof', expect.objectContaining({ method: 'POST' }))
    expect(onProofComplete.mock.calls[0][1].invented).toBe(false)
    expect(onProofComplete.mock.calls[0][1].proof_status).toBe('proven')
    expect(await screen.findByText(/oast_hit/)).toBeInTheDocument()
  })
})
