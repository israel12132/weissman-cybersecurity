import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import AiCommandConsole from './AiCommandConsole.jsx'

afterEach(cleanup)

const messages = [
  { id: 'u1', role: 'user', content: 'Show critical findings on prod' },
  {
    id: 'a1',
    role: 'assistant',
    content: '7 critical findings on production. Want me to launch containment?',
    actions: [{ id: 'run', label: 'Run containment playbook', intent: 'danger' }],
  },
]

describe('AiCommandConsole', () => {
  it('renders the multi-turn thread', () => {
    render(<AiCommandConsole messages={messages} onSubmit={() => {}} />)
    expect(screen.getByText('Show critical findings on prod')).toBeInTheDocument()
    expect(screen.getByText(/7 critical findings/)).toBeInTheDocument()
  })

  it('renders context grounding chips', () => {
    render(<AiCommandConsole messages={[]} onSubmit={() => {}} context={[{ label: 'Client: Acme' }]} />)
    expect(screen.getByText('Client: Acme')).toBeInTheDocument()
  })

  it('submits typed input and clears the field', () => {
    const onSubmit = vi.fn()
    render(<AiCommandConsole messages={[]} onSubmit={onSubmit} />)
    const input = screen.getByLabelText('Ask Weissman')
    fireEvent.change(input, { target: { value: 'run full scan on Acme' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send' }))
    expect(onSubmit).toHaveBeenCalledWith('run full scan on Acme')
    expect(input).toHaveValue('')
  })

  it('runs a one-click action from an assistant turn', () => {
    const onRunAction = vi.fn()
    render(<AiCommandConsole messages={messages} onSubmit={() => {}} onRunAction={onRunAction} />)
    fireEvent.click(screen.getByRole('button', { name: /Run containment playbook/i }))
    expect(onRunAction).toHaveBeenCalledWith(messages[1].actions[0], messages[1])
  })

  it('submits a suggested prompt on click', () => {
    const onSubmit = vi.fn()
    render(
      <AiCommandConsole
        messages={[]}
        onSubmit={onSubmit}
        suggestions={[{ label: 'Top risks today', prompt: 'What are my top risks today?' }]}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Top risks today' }))
    expect(onSubmit).toHaveBeenCalledWith('What are my top risks today?')
  })

  it('does not submit while busy', () => {
    const onSubmit = vi.fn()
    render(<AiCommandConsole messages={[]} onSubmit={onSubmit} busy />)
    const input = screen.getByLabelText('Ask Weissman')
    fireEvent.change(input, { target: { value: 'hello' } })
    fireEvent.submit(input.closest('form'))
    expect(onSubmit).not.toHaveBeenCalled()
  })
})
