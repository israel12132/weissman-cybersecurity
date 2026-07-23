import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import Progress from './Progress.jsx'

afterEach(cleanup)

describe('Progress', () => {
  it('renders a progressbar with the correct aria range and default label', () => {
    render(<Progress value={50} />)
    const bar = screen.getByRole('progressbar')
    expect(bar).toHaveAttribute('aria-valuemin', '0')
    expect(bar).toHaveAttribute('aria-valuemax', '100')
    expect(bar).toHaveAttribute('aria-valuenow', '50')
    expect(bar).toHaveAttribute('aria-label', 'Progress')
  })

  it('reflects an updated value on rerender', () => {
    const { rerender } = render(<Progress value={20} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '20')
    rerender(<Progress value={80} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '80')
  })

  it('clamps a value above max to max', () => {
    render(<Progress value={150} max={100} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100')
  })

  it('clamps a negative value to zero', () => {
    render(<Progress value={-20} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '0')
  })

  it('omits aria-valuenow and applies the sweep class when indeterminate', () => {
    const { container } = render(<Progress indeterminate />)
    const bar = screen.getByRole('progressbar')
    expect(bar).not.toHaveAttribute('aria-valuenow')
    expect(container.querySelector('.animate-progress-indeterminate')).toBeInTheDocument()
  })

  it('renders the percentage in the label row when showLabel is set', () => {
    render(<Progress value={42} showLabel />)
    expect(screen.getByText('42%')).toBeInTheDocument()
  })

  it('uses a custom label for both the accessible name and the label row', () => {
    render(<Progress value={30} showLabel label="Uploading" />)
    const bar = screen.getByRole('progressbar')
    expect(bar).toHaveAttribute('aria-label', 'Uploading')
    expect(screen.getByText('Uploading')).toBeInTheDocument()
  })

  it('spreads extra props onto the root element', () => {
    render(<Progress value={10} data-testid="pb" />)
    expect(screen.getByTestId('pb')).toBeInTheDocument()
  })
})
