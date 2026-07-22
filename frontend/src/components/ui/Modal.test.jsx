import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Modal from './Modal.jsx'

afterEach(cleanup)

describe('Modal', () => {
  it('renders a dialog with the title as its accessible name', () => {
    render(
      <Modal open onClose={() => {}} title="Delete asset">
        Are you sure?
      </Modal>,
    )
    const dialog = screen.getByRole('dialog', { name: 'Delete asset' })
    expect(dialog).toBeInTheDocument()
    expect(screen.getByText('Are you sure?')).toBeInTheDocument()
  })

  it('renders nothing when closed', () => {
    render(
      <Modal open={false} onClose={() => {}} title="Hidden">
        body
      </Modal>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('body')).not.toBeInTheDocument()
  })

  it('sets aria-modal and describes itself via the description', () => {
    render(
      <Modal open onClose={() => {}} title="Info" description="More detail here">
        body
      </Modal>,
    )
    const dialog = screen.getByRole('dialog', { name: 'Info' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAttribute('aria-describedby')
    expect(dialog).toHaveAccessibleDescription('More detail here')
  })

  it('calls onClose when the close button is clicked', () => {
    const onClose = vi.fn()
    render(
      <Modal open onClose={onClose} title="Closable">
        body
      </Modal>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when Escape is pressed', () => {
    const onClose = vi.fn()
    render(
      <Modal open onClose={onClose} title="Esc closes">
        body
      </Modal>,
    )
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('does not call onClose on Escape when closeOnEsc is false', () => {
    const onClose = vi.fn()
    render(
      <Modal open onClose={onClose} title="No esc" closeOnEsc={false}>
        body
      </Modal>,
    )
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(onClose).not.toHaveBeenCalled()
  })

  it('calls onClose when the overlay scrim is clicked', () => {
    const onClose = vi.fn()
    render(
      <Modal open onClose={onClose} title="Overlay">
        body
      </Modal>,
    )
    const scrim = screen.getByRole('dialog').parentElement
    fireEvent.mouseDown(scrim)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('hides the close button when hideClose is set', () => {
    render(
      <Modal open onClose={() => {}} title="No close" hideClose>
        body
      </Modal>,
    )
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
  })
})
