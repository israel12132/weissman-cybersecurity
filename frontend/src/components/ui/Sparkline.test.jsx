import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import Sparkline from './Sparkline.jsx'

afterEach(cleanup)

describe('Sparkline', () => {
  it('renders an accessible line + area path for a numeric series', () => {
    render(<Sparkline data={[1, 4, 2, 8, 5]} label="7-day trend" />)
    const svg = screen.getByRole('img', { name: '7-day trend' })
    expect(svg).toBeInTheDocument()
    // area type => two paths (fill + stroke)
    expect(svg.querySelectorAll('path').length).toBe(2)
  })

  it('is decorative (aria-hidden) when no label is given', () => {
    const { container } = render(<Sparkline data={[1, 2, 3]} />)
    const svg = container.querySelector('svg')
    expect(svg).toHaveAttribute('aria-hidden', 'true')
    expect(svg).not.toHaveAttribute('role')
  })

  it('renders a single stroke path in line mode', () => {
    render(<Sparkline data={[3, 1, 4]} type="line" label="line" />)
    const svg = screen.getByRole('img', { name: 'line' })
    expect(svg.querySelectorAll('path').length).toBe(1)
  })

  it('emphasizes the last point when showDot is set', () => {
    render(<Sparkline data={[1, 2, 3]} showDot label="dotted" />)
    expect(screen.getByRole('img', { name: 'dotted' }).querySelector('circle')).not.toBeNull()
  })

  it('does not crash on empty data and stays sized', () => {
    const { container } = render(<Sparkline data={[]} width={80} height={20} />)
    const svg = container.querySelector('svg')
    expect(svg).toBeInTheDocument()
    expect(svg).toHaveAttribute('width', '80')
    expect(svg.querySelector('path')).toBeNull()
  })

  it('accepts object points ({y}/{value})', () => {
    render(<Sparkline data={[{ y: 2 }, { value: 6 }, { y: 4 }]} label="objects" />)
    expect(screen.getByRole('img', { name: 'objects' })).toBeInTheDocument()
  })
})
