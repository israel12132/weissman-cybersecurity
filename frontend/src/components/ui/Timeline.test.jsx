import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import Timeline from './Timeline.jsx'

afterEach(cleanup)

const items = [
  { id: 1, title: 'Finding detected', description: 'KEV service exposed', timestamp: '09:12', variant: 'danger' },
  { id: 2, title: 'Triaged', timestamp: '09:20', variant: 'warning' },
  { id: 3, title: 'Remediated', timestamp: '10:05', variant: 'success' },
]

describe('Timeline', () => {
  it('renders an ordered list with one entry per item', () => {
    const { container } = render(<Timeline items={items} />)
    expect(container.querySelector('ol')).toBeInTheDocument()
    expect(container.querySelectorAll('li').length).toBe(3)
  })

  it('renders titles, descriptions and timestamps', () => {
    render(<Timeline items={items} />)
    expect(screen.getByText('Finding detected')).toBeInTheDocument()
    expect(screen.getByText('KEV service exposed')).toBeInTheDocument()
    expect(screen.getByText('10:05')).toBeInTheDocument()
  })

  it('shows an empty message when there are no items', () => {
    render(<Timeline items={[]} emptyMessage="Nothing yet" />)
    expect(screen.getByText('Nothing yet')).toBeInTheDocument()
  })

  it('renders a provided node icon', () => {
    const { container } = render(
      <Timeline items={[{ id: 1, title: 'X', icon: <svg data-testid="ic" /> }]} />,
    )
    expect(container.querySelector('[data-testid="ic"]')).toBeInTheDocument()
  })
})
