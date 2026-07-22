import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Popover from './Popover.jsx'

afterEach(cleanup)

describe('Popover', () => {
  it('renders the trigger button and keeps the panel closed initially', () => {
    render(
      <Popover trigger="Open menu">
        <div>Panel content</div>
      </Popover>,
    )
    const btn = screen.getByRole('button', { name: 'Open menu' })
    expect(btn).toHaveAttribute('aria-haspopup', 'dialog')
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    // Panel is rendered only when open.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('opens the panel on trigger click and reflects aria-expanded', () => {
    render(
      <Popover trigger="Open menu">
        <div>Panel content</div>
      </Popover>,
    )
    const btn = screen.getByRole('button', { name: 'Open menu' })
    fireEvent.click(btn)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Panel content')).toBeInTheDocument()
    expect(btn).toHaveAttribute('aria-expanded', 'true')
  })

  it('associates the dialog with the trigger via aria-labelledby (a11y)', () => {
    render(
      <Popover trigger="Details">
        <div>Body</div>
      </Popover>,
    )
    const btn = screen.getByRole('button', { name: 'Details' })
    fireEvent.click(btn)
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveAttribute('aria-labelledby', btn.id)
  })

  it('closes on Escape and returns focus to the trigger', () => {
    render(
      <Popover trigger="Open menu">
        <div>Panel content</div>
      </Popover>,
    )
    const btn = screen.getByRole('button', { name: 'Open menu' })
    fireEvent.click(btn)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(document.activeElement).toBe(btn)
  })

  it('closes on an outside mousedown', () => {
    render(
      <Popover trigger="Open menu">
        <div>Panel content</div>
      </Popover>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Open menu' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.mouseDown(document.body)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('is controlled by the open prop and fires onOpenChange without self-toggling', () => {
    const onOpenChange = vi.fn()
    const { rerender } = render(
      <Popover open={false} onOpenChange={onOpenChange} trigger="Toggle">
        <div>Controlled body</div>
      </Popover>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Toggle' }))
    // Controlled: request emitted but state does not change until the parent updates.
    expect(onOpenChange).toHaveBeenCalledWith(true)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    rerender(
      <Popover open onOpenChange={onOpenChange} trigger="Toggle">
        <div>Controlled body</div>
      </Popover>,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})
