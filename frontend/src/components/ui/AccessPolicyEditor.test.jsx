import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import AccessPolicyEditor from './AccessPolicyEditor.jsx'

afterEach(cleanup)

const rules = [
  { id: 'rule-1', effect: 'allow', subject: 'analyst', action: 'read', resource: 'findings', condition: '' },
]
const subjects = [{ value: 'analyst', label: 'Analyst' }, { value: 'admin', label: 'Admin' }]
const actions = [{ value: 'read', label: 'Read' }, { value: 'write', label: 'Write' }]
const resources = [{ value: 'findings', label: 'Findings' }]

describe('AccessPolicyEditor', () => {
  it('renders a row per rule with its effect', () => {
    render(<AccessPolicyEditor rules={rules} subjects={subjects} actions={actions} resources={resources} onChange={() => {}} />)
    expect(screen.getByLabelText('Effect')).toHaveValue('allow')
    expect(screen.getByLabelText('Subject')).toHaveValue('analyst')
  })

  it('reports an edited effect via onChange', () => {
    const onChange = vi.fn()
    render(<AccessPolicyEditor rules={rules} subjects={subjects} actions={actions} resources={resources} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('Effect'), { target: { value: 'deny' } })
    expect(onChange).toHaveBeenCalledWith([expect.objectContaining({ id: 'rule-1', effect: 'deny' })])
  })

  it('adds a new rule', () => {
    const onChange = vi.fn()
    render(<AccessPolicyEditor rules={rules} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: /Add rule/i }))
    expect(onChange).toHaveBeenCalled()
    expect(onChange.mock.calls[0][0].length).toBe(2)
  })

  it('removes a rule', () => {
    const onChange = vi.fn()
    render(<AccessPolicyEditor rules={rules} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove rule' }))
    expect(onChange).toHaveBeenCalledWith([])
  })

  it('warns when there are no rules (deny by default)', () => {
    render(<AccessPolicyEditor rules={[]} onChange={() => {}} />)
    expect(screen.getByText(/denied by default/)).toBeInTheDocument()
  })
})
