import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import CommandBar, { fuzzyScore, scoreCommand } from './CommandBar.jsx'

afterEach(cleanup)

const commands = [
  { id: 'scan', title: 'Run full scan', group: 'Actions', keywords: ['engine'], run: vi.fn() },
  { id: 'findings', title: 'Show critical findings', group: 'Navigate', run: vi.fn() },
  { id: 'isolate', title: 'Isolate host', group: 'Actions', run: vi.fn() },
]

describe('fuzzyScore / scoreCommand', () => {
  it('scores substring higher than subsequence, and 0 for no match', () => {
    expect(fuzzyScore('Run full scan', 'scan')).toBeGreaterThan(fuzzyScore('Run full scan', 'rfs'))
    expect(fuzzyScore('Run full scan', 'rfs')).toBeGreaterThan(0)
    expect(fuzzyScore('Run full scan', 'zzz')).toBe(0)
    expect(fuzzyScore('anything', '')).toBe(1)
  })

  it('matches a command via its keywords', () => {
    expect(scoreCommand(commands[0], 'engine')).toBeGreaterThan(0)
  })
})

describe('CommandBar', () => {
  it('renders all commands when open with an empty query', () => {
    render(<CommandBar open commands={commands} onOpenChange={() => {}} />)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Run full scan')).toBeInTheDocument()
    expect(screen.getByText('Isolate host')).toBeInTheDocument()
  })

  it('filters the list as the query narrows', () => {
    render(<CommandBar open commands={commands} onOpenChange={() => {}} />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'isolate' } })
    expect(screen.getByText('Isolate host')).toBeInTheDocument()
    expect(screen.queryByText('Run full scan')).not.toBeInTheDocument()
  })

  it('runs a command on click and closes', () => {
    const onOpenChange = vi.fn()
    render(<CommandBar open commands={commands} onOpenChange={onOpenChange} />)
    fireEvent.click(screen.getByText('Isolate host'))
    expect(commands[2].run).toHaveBeenCalled()
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('runs the active command on Enter', () => {
    render(<CommandBar open commands={commands} onOpenChange={() => {}} />)
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'scan' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(commands[0].run).toHaveBeenCalled()
  })

  it('appends AI suggestions from the natural-language resolver', async () => {
    const resolve = vi.fn().mockResolvedValue([
      { id: 'ai-1', title: 'Show findings from last 24h on prod', run: vi.fn() },
    ])
    render(
      <CommandBar open commands={commands} onOpenChange={() => {}} resolveNaturalLanguage={resolve} />,
    )
    fireEvent.change(screen.getByRole('combobox'), {
      target: { value: 'show me prod findings from yesterday' },
    })
    await waitFor(() => expect(resolve).toHaveBeenCalled())
    expect(await screen.findByText('Show findings from last 24h on prod')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    render(<CommandBar open={false} commands={commands} onOpenChange={() => {}} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
