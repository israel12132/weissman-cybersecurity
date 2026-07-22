import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import DryRunSimulator from './DryRunSimulator.jsx'

afterEach(cleanup)

const steps = [
  { id: 's1', label: 'Match trigger' },
  { id: 's2', label: 'Check KEV', evaluate: (e) => e?.kev === true },
  { id: 's3', label: 'Isolate host' },
]

describe('DryRunSimulator', () => {
  it('renders the steps and a run button', () => {
    render(<DryRunSimulator steps={steps} sampleEvent={{ kev: true }} />)
    expect(screen.getByRole('button', { name: /Run dry-run/i })).toBeInTheDocument()
    expect(screen.getByText('Match trigger')).toBeInTheDocument()
  })

  it('runs and produces a passing trace when evaluations pass', () => {
    const onComplete = vi.fn()
    render(<DryRunSimulator steps={steps} sampleEvent={{ kev: true }} onComplete={onComplete} />)
    fireEvent.click(screen.getByRole('button', { name: /Run dry-run/i }))
    expect(screen.getByText('Execution trace')).toBeInTheDocument()
    expect(onComplete).toHaveBeenCalled()
    expect(onComplete.mock.calls[0][0].length).toBe(3)
  })

  it('halts the trace at a failing step', () => {
    const onComplete = vi.fn()
    render(<DryRunSimulator steps={steps} sampleEvent={{ kev: false }} onComplete={onComplete} />)
    fireEvent.click(screen.getByRole('button', { name: /Run dry-run/i }))
    // s1 passes, s2 fails and halts → 2 trace entries.
    expect(onComplete.mock.calls[0][0].length).toBe(2)
    expect(screen.getByText('Failed — halted')).toBeInTheDocument()
  })
})
