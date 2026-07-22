import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import DashboardGrid from './DashboardGrid.jsx'

afterEach(cleanup)

const widgets = [
  { id: 'a', title: 'Findings', node: <div>findings-body</div> },
  { id: 'b', title: 'Engines', node: <div>engines-body</div> },
  { id: 'c', title: 'Risk', node: <div>risk-body</div> },
]

describe('DashboardGrid', () => {
  it('renders each widget title and body', () => {
    render(<DashboardGrid widgets={widgets} />)
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.getByText('engines-body')).toBeInTheDocument()
  })

  it('hides edit controls unless editable', () => {
    render(<DashboardGrid widgets={widgets} />)
    expect(screen.queryByRole('button', { name: /Remove/i })).not.toBeInTheDocument()
  })

  it('reorders a widget later via the move control', () => {
    const onReorder = vi.fn()
    render(<DashboardGrid widgets={widgets} editable onReorder={onReorder} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move Findings later' }))
    expect(onReorder).toHaveBeenCalled()
    const next = onReorder.mock.calls[0][0]
    expect(next.map((w) => w.id)).toEqual(['b', 'a', 'c'])
  })

  it('removes a widget', () => {
    const onRemove = vi.fn()
    render(<DashboardGrid widgets={widgets} editable onRemove={onRemove} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove Engines' }))
    expect(onRemove).toHaveBeenCalledWith('b')
  })

  it('disables moving the first widget earlier', () => {
    render(<DashboardGrid widgets={widgets} editable onReorder={() => {}} />)
    expect(screen.getByRole('button', { name: 'Move Findings earlier' })).toBeDisabled()
  })
})
