import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import UsageMeter from './UsageMeter.jsx'

afterEach(cleanup)

describe('UsageMeter', () => {
  it('renders the used/limit readout with unit', () => {
    render(<UsageMeter label="Scans" used={40} limit={100} unit="scans" />)
    expect(screen.getByText(/40 \/ 100 scans/)).toBeInTheDocument()
  })

  it('exposes progress via ARIA', () => {
    render(<UsageMeter label="Seats" used={25} limit={100} />)
    const bar = screen.getByRole('progressbar', { name: 'Seats' })
    expect(bar).toHaveAttribute('aria-valuenow', '25')
    expect(bar).toHaveAttribute('aria-valuemax', '100')
  })

  it('flags overage when used exceeds the limit', () => {
    render(<UsageMeter label="API" used={120} limit={100} />)
    expect(screen.getByText(/over limit/)).toBeInTheDocument()
    // Bar caps at 100%.
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100')
  })

  it('clamps a zero limit without dividing by zero', () => {
    render(<UsageMeter label="X" used={5} limit={0} />)
    const bar = screen.getByRole('progressbar')
    expect(bar).toHaveAttribute('aria-valuenow', '100')
  })
})
