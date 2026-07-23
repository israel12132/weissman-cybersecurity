import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Avatar, { AvatarGroup } from './Avatar.jsx'

afterEach(cleanup)

describe('Avatar', () => {
  it('renders an image with an accessible name from alt', () => {
    render(<Avatar src="/jane.png" alt="Jane Doe" />)
    const img = screen.getByRole('img', { name: 'Jane Doe' })
    expect(img).toBeInTheDocument()
    expect(img).toHaveAttribute('src', '/jane.png')
  })

  it('falls back to initials when the image fails to load', () => {
    render(<Avatar src="/broken.png" name="Ada Lovelace" />)
    const img = screen.getByRole('img')
    fireEvent.error(img)
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.getByText('AL')).toBeInTheDocument()
  })

  it('exposes the name to assistive tech while hiding the decorative initials', () => {
    render(<Avatar name="Grace Hopper" />)
    // Visible initials are aria-hidden (decorative)...
    const initials = screen.getByText('GH')
    expect(initials).toHaveAttribute('aria-hidden', 'true')
    // ...while the name is available to screen readers.
    expect(screen.getByText('Grace Hopper')).toBeInTheDocument()
  })

  it('renders a lucide User icon when there is no src and no name', () => {
    const { container } = render(<Avatar />)
    expect(container.querySelector('svg')).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  it('renders a presence status dot when status is set', () => {
    const { container } = render(<Avatar name="On Call" status="online" />)
    expect(container.querySelector('.bg-status-active')).toBeInTheDocument()
  })
})

describe('AvatarGroup', () => {
  it('collapses avatars beyond max into a +N overflow chip', () => {
    render(
      <AvatarGroup max={2}>
        <Avatar name="Aa Aa" />
        <Avatar name="Bb Bb" />
        <Avatar name="Cc Cc" />
        <Avatar name="Dd Dd" />
      </AvatarGroup>,
    )
    expect(screen.getByText('AA')).toBeInTheDocument()
    expect(screen.getByText('BB')).toBeInTheDocument()
    expect(screen.queryByText('CC')).not.toBeInTheDocument()
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('renders no overflow chip when children fit within max', () => {
    render(
      <AvatarGroup max={3}>
        <Avatar name="Xx Xx" />
        <Avatar name="Yy Yy" />
      </AvatarGroup>,
    )
    expect(screen.getByText('XX')).toBeInTheDocument()
    expect(screen.getByText('YY')).toBeInTheDocument()
    expect(screen.queryByText(/^\+/)).not.toBeInTheDocument()
  })
})
