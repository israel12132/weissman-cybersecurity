import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EvidenceNotice from './EvidenceNotice.jsx'
describe('EvidenceNotice', () => {
  it('renders children', () => {
    render(<EvidenceNotice>Live API evidence</EvidenceNotice>)
    expect(screen.getByText(/Live API evidence/)).toBeInTheDocument()
  })
  it('null when empty', () => {
    const { container } = render(<EvidenceNotice />)
    expect(container.firstChild).toBeNull()
  })
})