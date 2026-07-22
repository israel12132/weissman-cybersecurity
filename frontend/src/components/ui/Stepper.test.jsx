import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Stepper from './Stepper.jsx'

afterEach(cleanup)

const steps = [
  { id: 'a', label: 'Trigger', status: 'complete' },
  { id: 'b', label: 'Enrich', status: 'current' },
  { id: 'c', label: 'Contain', status: 'upcoming' },
  { id: 'd', label: 'Notify', status: 'error' },
]

describe('Stepper', () => {
  it('renders a list item per step with labels', () => {
    const { container } = render(<Stepper steps={steps} />)
    expect(container.querySelectorAll('li').length).toBe(4)
    expect(screen.getByText('Trigger')).toBeInTheDocument()
    expect(screen.getByText('Contain')).toBeInTheDocument()
  })

  it('marks the current step with aria-current="step"', () => {
    const { container } = render(<Stepper steps={steps} />)
    const current = container.querySelector('li[aria-current="step"]')
    expect(current).not.toBeNull()
    expect(current).toHaveTextContent('Enrich')
  })

  it('fires onStepClick with the step and index', () => {
    const onStepClick = vi.fn()
    render(<Stepper steps={steps} onStepClick={onStepClick} />)
    // The markers become buttons when interactive; click the first.
    fireEvent.click(screen.getAllByRole('button')[0])
    expect(onStepClick).toHaveBeenCalledWith(steps[0], 0)
  })

  it('supports vertical orientation', () => {
    const { container } = render(<Stepper steps={steps} orientation="vertical" />)
    expect(container.querySelector('ol')).toHaveClass('flex-col')
  })
})
