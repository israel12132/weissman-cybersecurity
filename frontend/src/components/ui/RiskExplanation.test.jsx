import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import RiskExplanation from './RiskExplanation.jsx'

afterEach(cleanup)

describe('RiskExplanation', () => {
  it('renders the narrative and likelihood/impact chips', () => {
    render(
      <RiskExplanation
        narrative="An attacker could pivot to the payments database."
        likelihood="high"
        impact="high"
      />,
    )
    expect(screen.getByText(/pivot to the payments database/)).toBeInTheDocument()
    expect(screen.getByText('Likelihood')).toBeInTheDocument()
    expect(screen.getByText('Impact')).toBeInTheDocument()
  })

  it('lists contributing factors', () => {
    render(
      <RiskExplanation
        narrative="x"
        factors={[
          { label: 'Internet-facing', level: 'high' },
          { label: 'KEV-listed', level: 'high' },
        ]}
      />,
    )
    expect(screen.getByText('Internet-facing')).toBeInTheDocument()
    expect(screen.getByText('KEV-listed')).toBeInTheDocument()
  })

  it('renders a recommendation callout', () => {
    render(<RiskExplanation narrative="x" recommendation="Apply the vendor hotfix within 24h." />)
    expect(screen.getByText(/vendor hotfix within 24h/)).toBeInTheDocument()
  })

  it('shows a skeleton and hides the narrative while loading', () => {
    render(<RiskExplanation narrative="secret" loading />)
    expect(screen.queryByText('secret')).not.toBeInTheDocument()
  })

  it('exposes an accessible region label', () => {
    render(<RiskExplanation narrative="x" />)
    expect(screen.getByRole('region', { name: 'AI risk explanation' })).toBeInTheDocument()
  })
})
