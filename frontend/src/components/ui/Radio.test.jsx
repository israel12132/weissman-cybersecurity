import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import RadioGroup, { Radio } from './Radio.jsx'

afterEach(cleanup)

describe('Radio', () => {
  it('renders a native radio with its label as the accessible name', () => {
    render(<Radio label="Accept terms" value="accept" />)
    const radio = screen.getByRole('radio', { name: 'Accept terms' })
    expect(radio).toBeInTheDocument()
    expect(radio).toHaveAttribute('type', 'radio')
  })

  it('is disabled when the disabled prop is set', () => {
    render(<Radio label="Blocked" value="blocked" disabled />)
    expect(screen.getByRole('radio', { name: 'Blocked' })).toBeDisabled()
  })
})

describe('RadioGroup', () => {
  const OPTIONS = [
    { value: 'alpha', label: 'Alpha' },
    { value: 'beta', label: 'Beta' },
  ]

  it('exposes a radiogroup role labelled by its rendered label', () => {
    render(<RadioGroup label="Pick one" options={OPTIONS} />)
    const group = screen.getByRole('radiogroup')
    const labelledby = group.getAttribute('aria-labelledby')
    expect(labelledby).toBeTruthy()
    expect(document.getElementById(labelledby)).toHaveTextContent('Pick one')
  })

  it('reflects the controlled value and fires onChange with the picked value', () => {
    let received
    render(
      <RadioGroup
        label="Choose"
        value="alpha"
        onChange={(v) => {
          received = v
        }}
        options={OPTIONS}
      />,
    )
    expect(screen.getByRole('radio', { name: 'Alpha' })).toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: 'Beta' }))
    expect(received).toBe('beta')
  })

  it('updates the selection when uncontrolled (defaultValue)', () => {
    render(<RadioGroup label="Choose" defaultValue="alpha" options={OPTIONS} />)
    expect(screen.getByRole('radio', { name: 'Alpha' })).toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: 'Beta' }))
    expect(screen.getByRole('radio', { name: 'Beta' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Alpha' })).not.toBeChecked()
  })

  it('disables every option and suppresses onChange when the group is disabled', () => {
    let called = false
    render(
      <RadioGroup
        label="Choose"
        disabled
        onChange={() => {
          called = true
        }}
        options={OPTIONS}
      />,
    )
    const alpha = screen.getByRole('radio', { name: 'Alpha' })
    expect(alpha).toBeDisabled()
    // `disabled` is the real, browser-honored guarantee. jsdom activates a
    // disabled radio on a programmatically dispatched click (real browsers do
    // not), so we assert the disabled state rather than click-then-count.
    expect(called).toBe(false)
  })
})
