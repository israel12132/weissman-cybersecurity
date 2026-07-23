import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import MiniHeatmap from './MiniHeatmap.jsx'

afterEach(cleanup)

describe('MiniHeatmap', () => {
  it('renders a 2D matrix as titled cells', () => {
    render(<MiniHeatmap data={[[0, 1], [2, 3]]} title="Threat map" />)
    // Root exposes the title as an image name.
    expect(screen.getByRole('img', { name: 'Threat map' })).toBeInTheDocument()
    // Each cell carries a "row,col: value" title; indices are used with no labels.
    expect(screen.getByTitle('0,0: 0')).toBeInTheDocument()
    expect(screen.getByTitle('1,1: 3')).toBeInTheDocument()
  })

  it('exposes an accessible name on the root (a11y)', () => {
    const { container } = render(<MiniHeatmap data={[[5]]} title="Coverage grid" />)
    const root = container.querySelector('[role="img"]')
    expect(root).toHaveAttribute('aria-label', 'Coverage grid')
  })

  it('calls onCellClick with coordinates and value when a cell is clicked', () => {
    const calls = []
    render(
      <MiniHeatmap
        data={[[5, 9]]}
        title="Clickable"
        onCellClick={(r, c, v) => calls.push([r, c, v])}
      />,
    )
    // Interactive cells become buttons under a labelled group.
    expect(screen.getByRole('group', { name: 'Clickable' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '0,1: 9' }))
    expect(calls).toEqual([[0, 1, 9]])
  })

  it('normalizes flat data and defaults missing cells to zero, with labels', () => {
    render(
      <MiniHeatmap
        data={[
          { row: 0, col: 0, value: 1 },
          { row: 1, col: 1, value: 4 },
        ]}
        rowLabels={['A', 'B']}
        colLabels={['X', 'Y']}
        title="Flat"
      />,
    )
    // Labels are rendered.
    expect(screen.getByText('A')).toBeInTheDocument()
    expect(screen.getByText('Y')).toBeInTheDocument()
    // Provided cell uses labels in its title.
    expect(screen.getByTitle('B,Y: 4')).toBeInTheDocument()
    // Missing (0,1) cell defaults to 0.
    expect(screen.getByTitle('A,Y: 0')).toBeInTheDocument()
  })

  it('renders no cells for empty data (edge case)', () => {
    const { container } = render(<MiniHeatmap data={[]} title="Empty" />)
    expect(screen.getByRole('img', { name: 'Empty' })).toBeInTheDocument()
    expect(container.querySelectorAll('button').length).toBe(0)
    expect(container.querySelectorAll('[title]').length).toBe(0)
  })
})
