import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import NodePalette from './NodePalette.jsx'

afterEach(cleanup)

describe('NodePalette', () => {
  it('renders the default node types', () => {
    render(<NodePalette />)
    expect(screen.getByRole('button', { name: 'Add Trigger node' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add Condition node' })).toBeInTheDocument()
  })

  it('adds a node on click', () => {
    const onAdd = vi.fn()
    render(<NodePalette onAdd={onAdd} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add Action node' }))
    expect(onAdd).toHaveBeenCalledWith('action')
  })

  it('sets the drag payload on drag start', () => {
    render(<NodePalette />)
    const setData = vi.fn()
    fireEvent.dragStart(screen.getByRole('button', { name: 'Add Notify node' }), {
      dataTransfer: { setData, effectAllowed: '' },
    })
    expect(setData).toHaveBeenCalledWith('application/weissman-node', 'notify')
  })
})
