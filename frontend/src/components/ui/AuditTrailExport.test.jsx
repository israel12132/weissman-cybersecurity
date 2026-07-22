import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import AuditTrailExport from './AuditTrailExport.jsx'

const entries = [
  { timestamp: 't1', actor: 'ada', action: 'login', target: 'console', result: 'success' },
  { timestamp: 't2', actor: 'grace', action: 'delete', target: 'finding:42', result: 'failure' },
  { timestamp: 't3', actor: 'ada', action: 'export', target: 'report', result: 'success' },
]

describe('AuditTrailExport', () => {
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })
  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
  })

  it('shows the total entry count', () => {
    render(<AuditTrailExport entries={entries} />)
    expect(screen.getByText('3 of 3 entries')).toBeInTheDocument()
  })

  it('filters by free text', () => {
    render(<AuditTrailExport entries={entries} />)
    fireEvent.change(screen.getByLabelText('Filter'), { target: { value: 'grace' } })
    expect(screen.getByText('1 of 3 entries')).toBeInTheDocument()
  })

  it('filters by result', () => {
    render(<AuditTrailExport entries={entries} />)
    fireEvent.change(screen.getByLabelText('Result'), { target: { value: 'failure' } })
    expect(screen.getByText('1 of 3 entries')).toBeInTheDocument()
  })

  it('exports the filtered set to CSV', () => {
    render(<AuditTrailExport entries={entries} />)
    fireEvent.click(screen.getByRole('button', { name: /Export CSV/i }))
    expect(URL.createObjectURL).toHaveBeenCalled()
  })

  it('disables export when nothing matches', () => {
    render(<AuditTrailExport entries={entries} />)
    fireEvent.change(screen.getByLabelText('Filter'), { target: { value: 'zzz-nomatch' } })
    expect(screen.getByRole('button', { name: /Export CSV/i })).toBeDisabled()
  })
})
