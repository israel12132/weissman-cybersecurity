import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import SwarmMap from './SwarmMap.jsx'

afterEach(cleanup)

const points = [
  { id: 'tlv', lat: 32, lon: 34.8, intensity: 0.9, label: 'Tel Aviv' },
  { id: 'nyc', lat: 40.7, lon: -74, intensity: 0.4, label: 'New York' },
]
const arcs = [{ from: { lat: 32, lon: 34.8 }, to: { lat: 40.7, lon: -74 } }]

describe('SwarmMap', () => {
  it('renders a labelled map region', () => {
    render(<SwarmMap points={points} arcs={arcs} title="Live swarm" />)
    expect(screen.getByRole('img', { name: 'Live swarm' })).toBeInTheDocument()
  })

  it('labels heat points with their name and intensity', () => {
    render(<SwarmMap points={points} />)
    expect(screen.getByLabelText(/Tel Aviv \(90%\)/)).toBeInTheDocument()
    expect(screen.getByLabelText(/New York \(40%\)/)).toBeInTheDocument()
  })

  it('makes points keyboard-selectable when onPointClick is given', () => {
    const onPointClick = vi.fn()
    render(<SwarmMap points={points} onPointClick={onPointClick} />)
    fireEvent.click(screen.getByRole('button', { name: /Tel Aviv/ }))
    expect(onPointClick).toHaveBeenCalledWith(points[0])
  })

  it('renders without points or arcs', () => {
    render(<SwarmMap points={[]} title="Empty" />)
    expect(screen.getByRole('img', { name: 'Empty' })).toBeInTheDocument()
  })
})
