import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Drawer from './Drawer.jsx'

afterEach(cleanup)

describe('Drawer', () => {
  it('renders a labelled dialog with its title, description, and body', () => {
    render(
      <Drawer open onClose={() => {}} title="Settings" description="Tune your workspace">
        <p>Panel content</p>
      </Drawer>,
    )
    const dialog = screen.getByRole('dialog', { name: 'Settings' })
    expect(dialog).toBeInTheDocument()
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(screen.getByText('Tune your workspace')).toBeInTheDocument()
    expect(screen.getByText('Panel content')).toBeInTheDocument()
  })

  it('renders nothing while closed', () => {
    render(
      <Drawer open={false} onClose={() => {}} title="Hidden">
        <p>Should not appear</p>
      </Drawer>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('Should not appear')).not.toBeInTheDocument()
  })

  it('fires onClose when the close button is clicked', () => {
    let calls = 0
    render(
      <Drawer open onClose={() => { calls += 1 }} title="Filters">
        <p>Body</p>
      </Drawer>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(calls).toBe(1)
  })

  it('closes on Escape by default and stays open when closeOnEsc is false', () => {
    let escapable = 0
    const { unmount } = render(
      <Drawer open onClose={() => { escapable += 1 }} title="A">
        <p>Body</p>
      </Drawer>,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(escapable).toBe(1)
    unmount()

    let locked = 0
    render(
      <Drawer open closeOnEsc={false} onClose={() => { locked += 1 }} title="B">
        <p>Body</p>
      </Drawer>,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(locked).toBe(0)
  })

  it('closes on scrim click only when closeOnOverlay is enabled', () => {
    let overlayClose = 0
    const { unmount } = render(
      <Drawer open onClose={() => { overlayClose += 1 }} title="Overlay on">
        <p>Body</p>
      </Drawer>,
    )
    fireEvent.click(document.querySelector('[role="presentation"]'))
    expect(overlayClose).toBe(1)
    unmount()

    let noClose = 0
    render(
      <Drawer open closeOnOverlay={false} onClose={() => { noClose += 1 }} title="Overlay off">
        <p>Body</p>
      </Drawer>,
    )
    fireEvent.click(document.querySelector('[role="presentation"]'))
    expect(noClose).toBe(0)
  })

  it('associates the description with the dialog via aria-describedby', () => {
    render(
      <Drawer open onClose={() => {}} title="Info" description="Extra detail">
        <p>Body</p>
      </Drawer>,
    )
    const dialog = screen.getByRole('dialog', { name: 'Info' })
    const describedBy = dialog.getAttribute('aria-describedby')
    expect(describedBy).toBeTruthy()
    expect(document.getElementById(describedBy)).toHaveTextContent('Extra detail')
  })

  it('renders footer content when provided', () => {
    render(
      <Drawer open onClose={() => {}} title="With footer" footer={<button type="button">Save</button>}>
        <p>Body</p>
      </Drawer>,
    )
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument()
  })
})
