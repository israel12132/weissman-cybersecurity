import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import PresenceStack from './PresenceStack.jsx'

afterEach(cleanup)

const users = [
  { id: 1, name: 'Ada' },
  { id: 2, name: 'Grace' },
  { id: 3, name: 'Alan' },
  { id: 4, name: 'Kay' },
  { id: 5, name: 'Lin' },
  { id: 6, name: 'Ravi' },
]

describe('PresenceStack', () => {
  it('shows a viewing count label', () => {
    render(<PresenceStack users={users.slice(0, 3)} />)
    expect(screen.getByText('3 viewing')).toBeInTheDocument()
  })

  it('caps visible avatars and shows an overflow chip', () => {
    render(<PresenceStack users={users} max={4} />)
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('exposes an accessible presence label', () => {
    render(<PresenceStack users={users.slice(0, 2)} showLabel={false} />)
    expect(screen.getByLabelText('2 viewing')).toBeInTheDocument()
  })
})
