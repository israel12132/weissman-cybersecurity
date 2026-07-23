import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import EvidenceGallery from './EvidenceGallery.jsx'

afterEach(cleanup)

const items = [
  { id: 'a', kind: 'image', src: '/a.png', alt: 'Screenshot A', caption: 'Login page' },
  { id: 'b', kind: 'log', caption: 'Access log', content: 'GET /admin 200' },
  { id: 'c', kind: 'file', caption: 'report.pdf' },
]

describe('EvidenceGallery', () => {
  it('renders a thumbnail button per item', () => {
    render(<EvidenceGallery items={items} />)
    expect(screen.getByRole('button', { name: 'Login page' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Access log' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'report.pdf' })).toBeInTheDocument()
  })

  it('opens a lightbox dialog when a thumbnail is clicked', () => {
    render(<EvidenceGallery items={items} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Access log' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toBeInTheDocument()
    expect(dialog).toHaveTextContent('GET /admin 200')
  })

  it('pages to the next item from the lightbox footer', () => {
    render(<EvidenceGallery items={items} />)
    fireEvent.click(screen.getByRole('button', { name: 'Login page' }))
    expect(screen.getByText('1 / 3')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next evidence' }))
    expect(screen.getByText('2 / 3')).toBeInTheDocument()
  })

  it('shows an empty message when there is no evidence', () => {
    render(<EvidenceGallery items={[]} emptyMessage="Nothing attached" />)
    expect(screen.getByText('Nothing attached')).toBeInTheDocument()
  })
})
