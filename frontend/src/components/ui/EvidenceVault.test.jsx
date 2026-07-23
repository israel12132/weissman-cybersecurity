import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import EvidenceVault from './EvidenceVault.jsx'

afterEach(cleanup)

const items = [
  { id: '1', name: 'memory-dump.raw', hash: 'a'.repeat(64), sealedAt: '09:12', verified: true, size: '2.4 GB' },
  { id: '2', name: 'tampered.log', hash: 'b'.repeat(64), sealedAt: '09:20', verified: false, size: '12 KB' },
]

describe('EvidenceVault', () => {
  it('lists artifacts with a truncated hash', () => {
    render(<EvidenceVault items={items} />)
    expect(screen.getByText('memory-dump.raw')).toBeInTheDocument()
    expect(screen.getByText(/sha256:aaaaaaaa…aaaaaa/)).toBeInTheDocument()
  })

  it('marks a tampered artifact', () => {
    render(<EvidenceVault items={items} />)
    expect(screen.getByText('Tampered')).toBeInTheDocument()
    expect(screen.getByText('Verified')).toBeInTheDocument()
  })

  it('fires verify and download callbacks', () => {
    const onVerify = vi.fn()
    const onDownload = vi.fn()
    render(<EvidenceVault items={items} onVerify={onVerify} onDownload={onDownload} />)
    fireEvent.click(screen.getByRole('button', { name: 'Verify memory-dump.raw' }))
    expect(onVerify).toHaveBeenCalledWith('1')
    fireEvent.click(screen.getByRole('button', { name: 'Download tampered.log' }))
    expect(onDownload).toHaveBeenCalledWith('2')
  })

  it('shows an empty message for an empty vault', () => {
    render(<EvidenceVault items={[]} emptyMessage="Nothing sealed" />)
    expect(screen.getByText('Nothing sealed')).toBeInTheDocument()
  })
})
