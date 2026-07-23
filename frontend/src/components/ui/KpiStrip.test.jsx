import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import KpiStrip, { KpiTile } from './KpiStrip.jsx'

afterEach(cleanup)

describe('KpiTile', () => {
  it('renders label, value and unit', () => {
    render(<KpiTile label="Open findings" value={142} unit="items" />)
    expect(screen.getByText('Open findings')).toBeInTheDocument()
    expect(screen.getByText('142')).toBeInTheDocument()
    expect(screen.getByText('items')).toBeInTheDocument()
  })

  it('becomes a keyboard-operable button that drills down when onClick is set', () => {
    const onClick = vi.fn()
    render(<KpiTile label="Critical" value={7} onClick={onClick} />)
    const btn = screen.getByRole('button', { name: /Critical: 7/i })
    fireEvent.click(btn)
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('shows a positive delta as an increase', () => {
    render(<KpiTile label="Resolved" value={30} delta={5} deltaLabel="vs 24h" />)
    expect(screen.getByText('+5')).toBeInTheDocument()
    expect(screen.getByText('vs 24h')).toBeInTheDocument()
  })

  it('renders a trend sparkline when provided', () => {
    const { container } = render(<KpiTile label="Trend" value={9} trend={[1, 2, 3, 2, 5]} />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })

  it('renders a skeleton while loading (no value shown)', () => {
    render(<KpiTile label="Loading" value={99} loading />)
    expect(screen.queryByText('99')).not.toBeInTheDocument()
  })
})

describe('KpiStrip', () => {
  it('renders a tile per item', () => {
    render(
      <KpiStrip
        items={[
          { label: 'A', value: 1 },
          { label: 'B', value: 2 },
          { label: 'C', value: 3 },
        ]}
      />,
    )
    expect(screen.getByText('A')).toBeInTheDocument()
    expect(screen.getByText('B')).toBeInTheDocument()
    expect(screen.getByText('C')).toBeInTheDocument()
  })
})
