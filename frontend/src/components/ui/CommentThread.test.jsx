import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import CommentThread from './CommentThread.jsx'

afterEach(cleanup)

const comments = [
  { id: 1, author: { name: 'Ada' }, body: 'Confirmed exploit in staging', timestamp: '09:12' },
  { id: 2, author: { name: 'Grace' }, body: 'Rolling the hotfix now', timestamp: '09:20' },
]

describe('CommentThread', () => {
  it('renders comments with authors', () => {
    render(<CommentThread comments={comments} onSubmit={() => {}} />)
    // Bodies are unique; assert those plus that the author name is present
    // (the name also appears in the avatar's sr-only label, so allow multiple).
    expect(screen.getByText('Confirmed exploit in staging')).toBeInTheDocument()
    expect(screen.getByText('Rolling the hotfix now')).toBeInTheDocument()
    expect(screen.getAllByText('Grace').length).toBeGreaterThan(0)
  })

  it('posts a new comment and clears the field', () => {
    const onSubmit = vi.fn()
    render(<CommentThread comments={comments} onSubmit={onSubmit} />)
    const input = screen.getByLabelText('Add a comment')
    fireEvent.change(input, { target: { value: 'Looks contained' } })
    fireEvent.click(screen.getByRole('button', { name: 'Post comment' }))
    expect(onSubmit).toHaveBeenCalledWith('Looks contained')
    expect(input).toHaveValue('')
  })

  it('shows an empty state when there are no comments', () => {
    render(<CommentThread comments={[]} onSubmit={() => {}} emptyMessage="Be the first" />)
    expect(screen.getByText('Be the first')).toBeInTheDocument()
  })
})
