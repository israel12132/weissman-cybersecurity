import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import PlaybookInspector from './PlaybookInspector.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key) => key,
    i18n: { language: 'en', dir: () => 'ltr' },
  }),
}))

afterEach(cleanup)

describe('PlaybookInspector', () => {
  it('shows an empty hint when nothing is selected', () => {
    render(<PlaybookInspector />)
    expect(screen.getByText('playbooks.inspector.no_selection')).toBeInTheDocument()
  })

  it('edits trigger conditions on the selected trigger node', () => {
    const onPatchNode = vi.fn()
    render(
      <PlaybookInspector
        node={{
          id: 'n1',
          data: { kind: 'trigger', nodeType: 'trigger', trigger: { severity: [] } },
        }}
        onPatchNode={onPatchNode}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'playbooks.severity.critical' }))
    expect(onPatchNode).toHaveBeenCalled()
    const [, patch] = onPatchNode.mock.calls.at(-1)
    expect(patch.trigger.severity).toContain('critical')
  })

  it('changes action kind and params', () => {
    const onPatchNode = vi.fn()
    render(
      <PlaybookInspector
        node={{
          id: 'n2',
          data: { kind: 'set_status', nodeType: 'action', params: { status: 'IN_PROGRESS' } },
        }}
        onPatchNode={onPatchNode}
        onDeleteNode={vi.fn()}
      />,
    )
    fireEvent.change(screen.getByLabelText('playbooks.field.status'), { target: { value: 'FIXED' } })
    expect(onPatchNode).toHaveBeenCalledWith('n2', { params: { status: 'FIXED' } })
  })

  it('deletes an edge from the inspector', () => {
    const onDeleteEdge = vi.fn()
    render(
      <PlaybookInspector
        edge={{ id: 'e-n1-n2', source: 'n1', target: 'n2' }}
        onDeleteEdge={onDeleteEdge}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'playbooks.inspector.delete_edge' }))
    expect(onDeleteEdge).toHaveBeenCalledWith('e-n1-n2')
  })
})
