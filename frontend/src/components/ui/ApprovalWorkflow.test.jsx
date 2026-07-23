import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import ApprovalWorkflow from './ApprovalWorkflow.jsx'

afterEach(cleanup)

const stages = [
  { id: 'author', label: 'Author', approver: 'Ada', status: 'approved' },
  { id: 'lead', label: 'Team lead', approver: 'Grace', status: 'pending' },
  { id: 'ciso', label: 'CISO', approver: 'Alan', status: 'upcoming' },
]

describe('ApprovalWorkflow', () => {
  it('renders the approval chain', () => {
    render(<ApprovalWorkflow stages={stages} />)
    expect(screen.getByText('Author')).toBeInTheDocument()
    expect(screen.getByText('CISO')).toBeInTheDocument()
  })

  it('exposes approve/reject for the pending stage', () => {
    const onApprove = vi.fn()
    render(<ApprovalWorkflow stages={stages} onApprove={onApprove} />)
    expect(screen.getByText(/Awaiting/)).toHaveTextContent('Team lead')
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(onApprove).toHaveBeenCalledWith('lead')
  })

  it('calls onReject with the pending stage id', () => {
    const onReject = vi.fn()
    render(<ApprovalWorkflow stages={stages} onReject={onReject} />)
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }))
    expect(onReject).toHaveBeenCalledWith('lead')
  })

  it('shows completion when there is no pending stage', () => {
    render(
      <ApprovalWorkflow
        stages={[{ id: 'a', label: 'Author', status: 'approved' }]}
      />,
    )
    expect(screen.getByText('All approvals complete.')).toBeInTheDocument()
  })
})
