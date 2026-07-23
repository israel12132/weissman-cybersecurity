import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import FindingDrawerV2 from './FindingDrawerV2.jsx'

afterEach(cleanup)

const props = {
  finding: { title: 'GlobalProtect RCE', severity: 'critical', kev: true, host: 'prod-web-01', cve: 'CVE-2024-3400' },
  risk: { narrative: 'Internet-facing KEV RCE next to payments.', likelihood: 'high', impact: 'high' },
  attackPath: [
    { id: 'a', label: 'Recon', status: 'done' },
    { id: 'b', label: 'Access', status: 'active' },
  ],
  timeline: [{ id: 1, title: 'Detected', timestamp: '09:12', variant: 'danger' }],
  evidence: [{ id: 'e', kind: 'log', caption: 'Access log', content: 'GET /ssl-vpn' }],
  comments: [{ id: 'c', author: { name: 'Ada' }, body: 'Confirmed' }],
  viewers: [{ id: 'u', name: 'Grace' }],
}

describe('FindingDrawerV2', () => {
  it('renders nothing when closed', () => {
    render(<FindingDrawerV2 open={false} onClose={() => {}} {...props} />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('renders the finding header with severity and KEV', () => {
    render(<FindingDrawerV2 open onClose={() => {}} {...props} />)
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('GlobalProtect RCE')
    expect(dialog).toHaveTextContent('prod-web-01')
    // Overview tab shows the AI risk narrative by default.
    expect(screen.getByText(/Internet-facing KEV RCE/)).toBeInTheDocument()
  })

  it('switches to the Timeline and Discussion tabs', () => {
    render(<FindingDrawerV2 open onClose={() => {}} {...props} />)
    fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
    expect(screen.getByText('Detected')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Discussion' }))
    expect(screen.getByText('Confirmed')).toBeInTheDocument()
  })

  it('posts a comment from the discussion tab', () => {
    const onComment = vi.fn()
    render(<FindingDrawerV2 open onClose={() => {}} {...props} onComment={onComment} />)
    fireEvent.click(screen.getByRole('tab', { name: 'Discussion' }))
    fireEvent.change(screen.getByLabelText('Add a comment'), { target: { value: 'Contained' } })
    fireEvent.click(screen.getByRole('button', { name: 'Post comment' }))
    expect(onComment).toHaveBeenCalledWith('Contained')
  })
})
