import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import KillChainPath from './KillChainPath.jsx'

afterEach(cleanup)

const stages = [
  { id: 'recon', label: 'Recon', status: 'done' },
  { id: 'access', label: 'Initial access', status: 'active' },
  { id: 'exfil', label: 'Exfiltration', status: 'blocked', detail: 'DLP blocked' },
  { id: 'impact', label: 'Impact', status: 'pending' },
]

describe('KillChainPath', () => {
  it('renders a labelled list with one node per stage', () => {
    render(<KillChainPath stages={stages} title="Kill chain" />)
    const list = screen.getByRole('list', { name: 'Kill chain' })
    expect(list).toBeInTheDocument()
    expect(screen.getByText('Recon')).toBeInTheDocument()
    expect(screen.getByText('Impact')).toBeInTheDocument()
  })

  it('marks the active stage with aria-current="step"', () => {
    const { container } = render(<KillChainPath stages={stages} />)
    expect(container.querySelector('[aria-current="step"]')).not.toBeNull()
  })

  it('invokes onStageClick with the stage and index', () => {
    const onStageClick = vi.fn()
    render(<KillChainPath stages={stages} onStageClick={onStageClick} />)
    fireEvent.click(screen.getByRole('button', { name: /Recon: done/i }))
    expect(onStageClick).toHaveBeenCalledWith(stages[0], 0)
  })

  it('renders an empty message when there are no stages', () => {
    render(<KillChainPath stages={[]} emptyMessage="No path" />)
    expect(screen.getByText('No path')).toBeInTheDocument()
  })
})
