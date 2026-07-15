import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EmptyState from './EmptyState.jsx'

describe('EmptyState', () => {
  it('renders title and body', () => {
    render(<EmptyState title="Nothing here" body="Come back later." />)
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
    expect(screen.getByText('Come back later.')).toBeInTheDocument()
  })

  it('supports the description alias for body', () => {
    render(<EmptyState title="X" description="via description" />)
    expect(screen.getByText('via description')).toBeInTheDocument()
  })

  it('renders a known lucide icon key as an svg', () => {
    const { container } = render(<EmptyState icon="shield" title="Secured" />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })

  it('renders an unknown string icon (emoji) verbatim instead of defaulting to inbox', () => {
    const { container } = render(<EmptyState icon="🎯" title="Targeted" />)
    // Emoji is rendered as text, not swapped for a lucide svg.
    expect(container.querySelector('svg')).not.toBeInTheDocument()
    expect(screen.getByText('🎯')).toBeInTheDocument()
  })

  it('exposes a status role for assistive tech', () => {
    const { container } = render(<EmptyState title="Empty" />)
    expect(container.querySelector('[role="status"]')).toBeInTheDocument()
  })
})
