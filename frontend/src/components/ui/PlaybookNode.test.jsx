import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import PlaybookNode from './PlaybookNode.jsx'

afterEach(cleanup)

describe('PlaybookNode', () => {
  it('renders the type label, title and summary', () => {
    render(<PlaybookNode type="trigger" title="On critical finding" summary="severity = critical" />)
    expect(screen.getByText('Trigger')).toBeInTheDocument()
    expect(screen.getByText('On critical finding')).toBeInTheDocument()
    expect(screen.getByText('severity = critical')).toBeInTheDocument()
  })

  it('is a pressable button reflecting selection when onClick is given', () => {
    const onClick = vi.fn()
    render(<PlaybookNode title="Isolate host" onClick={onClick} selected />)
    const btn = screen.getByRole('button')
    expect(btn).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(btn)
    expect(onClick).toHaveBeenCalled()
  })

  it('renders two labelled output ports for a condition node', () => {
    const { container } = render(<PlaybookNode type="condition" title="Is KEV?" />)
    expect(container.querySelector('[title="true"]')).not.toBeNull()
    expect(container.querySelector('[title="false"]')).not.toBeNull()
  })

  it('shows a spinning status icon while running', () => {
    const { container } = render(<PlaybookNode title="Run" status="running" />)
    expect(container.querySelector('.animate-spin')).not.toBeNull()
  })

  it('renders as a non-interactive div without onClick', () => {
    render(<PlaybookNode title="Static" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
