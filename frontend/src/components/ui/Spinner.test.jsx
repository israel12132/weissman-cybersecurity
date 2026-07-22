import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import Spinner from './Spinner.jsx'

afterEach(cleanup)

describe('Spinner', () => {
  it('renders a status role with the default sr-only label', () => {
    render(<Spinner />)
    const status = screen.getByRole('status')
    expect(status).toBeInTheDocument()
    expect(screen.getByText('Loading')).toBeInTheDocument()
  })

  it('renders a custom label for assistive tech', () => {
    render(<Spinner label="Fetching alerts" />)
    // The status live region announces its content; the label lives in the
    // sr-only span, so assert on the region's text content (role="status"
    // does not take its accessible name from content).
    expect(screen.getByRole('status')).toHaveTextContent('Fetching alerts')
  })

  it('renders a spinning, decorative svg', () => {
    const { container } = render(<Spinner />)
    const svg = container.querySelector('svg')
    expect(svg).toBeInTheDocument()
    expect(svg).toHaveClass('animate-spin')
    expect(svg).toHaveAttribute('aria-hidden', 'true')
  })

  it('applies the requested size class and merges a custom className onto the svg', () => {
    const { container } = render(<Spinner size="lg" className="custom-class" />)
    const svg = container.querySelector('svg')
    expect(svg).toHaveClass('size-6')
    expect(svg).toHaveClass('custom-class')
  })

  it('falls back to the md size for an unknown size', () => {
    const { container } = render(<Spinner size="nope" />)
    expect(container.querySelector('svg')).toHaveClass('size-4')
  })
})
