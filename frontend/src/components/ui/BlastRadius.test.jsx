import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import BlastRadius from './BlastRadius.jsx'

afterEach(cleanup)

// Mirror the component's formatter so assertions are locale-independent.
const usd = (n) =>
  new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  }).format(n)

describe('BlastRadius', () => {
  it('renders the SLE and ALE headline figures', () => {
    render(<BlastRadius sle={100000} ale={250000} />)
    expect(screen.getByText(usd(100000))).toBeInTheDocument()
    expect(screen.getByText(usd(250000))).toBeInTheDocument()
  })

  it('renders crown jewel names with proportional bar widths', () => {
    const { container } = render(
      <BlastRadius
        crownJewels={[
          { name: 'Billing database', value: 500000 },
          { name: 'Auth service', value: 250000 },
        ]}
      />,
    )
    expect(screen.getByText('Billing database')).toBeInTheDocument()
    expect(screen.getByText('Auth service')).toBeInTheDocument()

    // Only the two proportional fills carry an inline width style.
    const fills = container.querySelectorAll('span[style]')
    expect(fills).toHaveLength(2)
    expect(fills[0].style.width).toBe('100%') // largest value → full bar
    expect(fills[1].style.width).toBe('50%') // half of the max
  })

  it('spreads props onto the root and forwards click handling', () => {
    let clicks = 0
    render(<BlastRadius onClick={() => { clicks += 1 }} />)
    fireEvent.click(screen.getByRole('region', { name: 'Financial blast radius' }))
    expect(clicks).toBe(1)
  })

  it('labels the region with the title', () => {
    render(<BlastRadius title="Q3 exposure" />)
    const region = screen.getByRole('region', { name: 'Q3 exposure' })
    expect(region).toHaveAttribute('aria-label', 'Q3 exposure')
  })

  it('shows an empty message and zero figures when there is no data', () => {
    render(<BlastRadius />)
    expect(screen.getByText('No crown jewels mapped')).toBeInTheDocument()
    // Both SLE and ALE default to zero.
    expect(screen.getAllByText(usd(0))).toHaveLength(2)
  })

  it('guards divide-by-zero when every crown jewel value is zero', () => {
    const { container } = render(
      <BlastRadius crownJewels={[{ name: 'Idle asset', value: 0 }]} />,
    )
    const fill = container.querySelector('span[style]')
    expect(fill.style.width).toBe('0%')
  })
})
