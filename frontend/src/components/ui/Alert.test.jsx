import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Alert from './Alert.jsx'

afterEach(cleanup)

describe('Alert', () => {
  it('renders title and children with a status role by default', () => {
    render(<Alert title="Heads up">Something happened</Alert>)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText('Heads up')).toBeInTheDocument()
    expect(screen.getByText('Something happened')).toBeInTheDocument()
  })

  it('uses the assertive alert role for the danger variant', () => {
    render(<Alert variant="danger">Critical failure detected</Alert>)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('fires onDismiss when the dismiss button is clicked', () => {
    let dismissed = 0
    render(
      <Alert dismissible onDismiss={() => { dismissed += 1 }}>
        Closable notice
      </Alert>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(dismissed).toBe(1)
  })

  it('does not render a dismiss button unless dismissible', () => {
    render(<Alert>Static notice</Alert>)
    expect(
      screen.queryByRole('button', { name: 'Dismiss' }),
    ).not.toBeInTheDocument()
  })

  it('renders a custom action node in the action row', () => {
    render(
      <Alert action={<button type="button">Retry</button>}>
        Upload failed
      </Alert>,
    )
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
