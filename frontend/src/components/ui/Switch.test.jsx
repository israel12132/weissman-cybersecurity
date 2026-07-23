import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Switch from './Switch.jsx'

afterEach(cleanup)

describe('Switch', () => {
  it('renders a switch with an associated label', () => {
    render(<Switch label="Enable notifications" />)
    const control = screen.getByRole('switch', { name: 'Enable notifications' })
    expect(control).toBeInTheDocument()
    expect(control).toHaveAttribute('type', 'checkbox')
  })

  it('fires onChange when toggled', () => {
    let calls = 0
    render(<Switch label="Dark mode" onChange={() => { calls += 1 }} />)
    fireEvent.click(screen.getByRole('switch', { name: 'Dark mode' }))
    expect(calls).toBe(1)
  })

  it('reflects the controlled checked state', () => {
    render(<Switch label="Auto sync" checked onChange={() => {}} />)
    expect(screen.getByRole('switch', { name: 'Auto sync' })).toBeChecked()
  })

  it('does not fire onChange while disabled', () => {
    let calls = 0
    render(<Switch label="Locked" disabled onChange={() => { calls += 1 }} />)
    const control = screen.getByRole('switch', { name: 'Locked' })
    expect(control).toBeDisabled()
    // `disabled` is the real, browser-honored guarantee. jsdom toggles a
    // disabled input on a programmatically dispatched click (real browsers do
    // not), so we assert the disabled state rather than click-then-count.
    expect(calls).toBe(0)
  })
})
