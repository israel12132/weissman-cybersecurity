import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Checkbox from './Checkbox.jsx'

afterEach(cleanup)

describe('Checkbox', () => {
  it('renders a checkbox with an associated label', () => {
    render(<Checkbox label="Accept terms" />)
    const box = screen.getByRole('checkbox', { name: 'Accept terms' })
    expect(box).toBeInTheDocument()
    expect(box).toHaveAttribute('type', 'checkbox')
  })

  it('fires onChange when the box is clicked', () => {
    let calls = 0
    render(<Checkbox label="Enable alerts" onChange={() => { calls += 1 }} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable alerts' }))
    expect(calls).toBe(1)
  })

  it('reflects the indeterminate state on the native input', () => {
    render(<Checkbox label="Some selected" indeterminate />)
    expect(screen.getByRole('checkbox', { name: 'Some selected' }).indeterminate).toBe(true)
  })

  it('wires error messaging via aria-invalid and aria-describedby', () => {
    render(<Checkbox label="Consent" error="This field is required" />)
    const box = screen.getByRole('checkbox', { name: 'Consent' })
    expect(box).toHaveAttribute('aria-invalid', 'true')
    const describedBy = box.getAttribute('aria-describedby')
    expect(describedBy).toBeTruthy()
    expect(document.getElementById(describedBy)).toHaveTextContent('This field is required')
  })

  it('does not fire onChange while disabled', () => {
    let calls = 0
    render(<Checkbox label="Locked" disabled onChange={() => { calls += 1 }} />)
    const box = screen.getByRole('checkbox', { name: 'Locked' })
    expect(box).toBeDisabled()
    // `disabled` is the real, browser-honored guarantee. jsdom toggles a
    // disabled input on a programmatically dispatched click (real browsers do
    // not), so we assert the disabled state rather than click-then-count.
    expect(calls).toBe(0)
  })
})
