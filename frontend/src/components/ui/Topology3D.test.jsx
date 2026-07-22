import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Topology3D from './Topology3D.jsx'

afterEach(cleanup)

const nodes = [
  { id: 'a', label: 'prod-web-01', severity: 'critical' },
  { id: 'b', label: 'db-01', severity: 'high' },
  { id: 'c', label: 'edge-gw', severity: 'info' },
]
const links = [
  { source: 'a', target: 'b' },
  { source: 'a', target: 'c' },
]

// jsdom has no WebGL, so the component exercises its guard + accessible fallback.
describe('Topology3D', () => {
  it('mounts without crashing and exposes an accessible topology region', () => {
    render(<Topology3D nodes={nodes} links={links} />)
    expect(screen.getByRole('img', { name: '3D network topology' })).toBeInTheDocument()
  })

  it('renders an accessible node list (the WebGL fallback + selection layer)', () => {
    render(<Topology3D nodes={nodes} links={links} />)
    const list = screen.getByRole('list', { name: 'Topology nodes' })
    expect(list).toBeInTheDocument()
    expect(screen.getByText('prod-web-01')).toBeInTheDocument()
    expect(screen.getByText('edge-gw')).toBeInTheDocument()
  })

  it('selects a node via the keyboard-navigable list', () => {
    const onNodeClick = vi.fn()
    render(<Topology3D nodes={nodes} links={links} onNodeClick={onNodeClick} />)
    fireEvent.click(screen.getByRole('button', { name: /db-01/ }))
    expect(onNodeClick).toHaveBeenCalledWith(nodes[1])
  })

  it('handles an empty graph', () => {
    render(<Topology3D nodes={[]} />)
    expect(screen.getByRole('img', { name: '3D network topology' })).toBeInTheDocument()
  })
})
