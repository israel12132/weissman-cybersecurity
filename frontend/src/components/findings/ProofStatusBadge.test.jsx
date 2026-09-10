import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import ProofStatusBadge, { proofStatusOf } from './ProofStatusBadge.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))

describe('ProofStatusBadge', () => {
  it('renders proven with the i18n key', () => {
    render(<ProofStatusBadge status="proven" />)
    expect(screen.getByTestId('proof-status-badge')).toHaveAttribute('data-proof-status', 'proven')
    expect(screen.getByText('findings.proof.proven')).toBeInTheDocument()
  })

  it('falls back to observed for unknown statuses', () => {
    expect(proofStatusOf({ proof_status: 'invented' })).toBe('observed')
    render(<ProofStatusBadge status="nope" compact />)
    expect(screen.getByTestId('proof-status-badge')).toHaveAttribute('data-proof-status', 'observed')
  })
})
