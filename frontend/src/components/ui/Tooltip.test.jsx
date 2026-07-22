import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Tooltip from './Tooltip.jsx'

afterEach(cleanup)

describe('Tooltip', () => {
  it('renders its trigger child and no tooltip while idle', () => {
    render(
      <Tooltip content="Extra info">
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('shows the tooltip immediately on focus with role="tooltip" and its content', () => {
    render(
      <Tooltip content="Focus hint">
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    fireEvent.focus(screen.getByRole('button', { name: 'Trigger' }))
    const tip = screen.getByRole('tooltip')
    expect(tip).toBeInTheDocument()
    expect(tip).toHaveTextContent('Focus hint')
  })

  it('associates the trigger with the tooltip via aria-describedby', () => {
    render(
      <Tooltip content="Described by me">
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    const btn = screen.getByRole('button', { name: 'Trigger' })
    fireEvent.focus(btn)
    const tip = screen.getByRole('tooltip')
    // The handlers/aria live on the span wrapping the trigger child.
    expect(btn.parentElement).toHaveAttribute('aria-describedby', tip.id)
  })

  it('hides the tooltip on blur', () => {
    render(
      <Tooltip content="Bye on blur">
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    const btn = screen.getByRole('button', { name: 'Trigger' })
    fireEvent.focus(btn)
    expect(screen.getByRole('tooltip')).toBeInTheDocument()
    fireEvent.blur(btn)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('dismisses the tooltip on Escape', () => {
    render(
      <Tooltip content="Escapable">
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    const btn = screen.getByRole('button', { name: 'Trigger' })
    fireEvent.focus(btn)
    expect(screen.getByRole('tooltip')).toBeInTheDocument()
    fireEvent.keyDown(btn, { key: 'Escape' })
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('shows on hover without delay when delay=0 and hides on mouse leave', () => {
    render(
      <Tooltip content="Hover hint" delay={0}>
        <button type="button">Trigger</button>
      </Tooltip>,
    )
    const btn = screen.getByRole('button', { name: 'Trigger' })
    // React derives onMouseEnter/onMouseLeave from the native mouseover/mouseout
    // events, so fire those (mouseEnter/mouseLeave do not trigger the handlers).
    fireEvent.mouseOver(btn)
    expect(screen.getByRole('tooltip')).toHaveTextContent('Hover hint')
    fireEvent.mouseOut(btn)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})
