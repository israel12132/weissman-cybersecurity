import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import SmartFilterBar from './SmartFilterBar.jsx'

afterEach(cleanup)

describe('SmartFilterBar', () => {
  it('renders a pill for each active filter as "label: value"', () => {
    render(
      <SmartFilterBar
        filters={[{ id: 'sev', label: 'Severity', value: 'Critical' }]}
      />,
    )
    expect(screen.getByText('Severity')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('formats numeric filter values with Intl.NumberFormat', () => {
    render(
      <SmartFilterBar filters={[{ id: 'assets', label: 'Assets', value: 1234567 }]} />,
    )
    const expected = new Intl.NumberFormat().format(1234567)
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('calls onRemove with the filter id when the pill X is clicked', () => {
    let removed = null
    render(
      <SmartFilterBar
        filters={[{ id: 'sev', label: 'Severity', value: 'High' }]}
        onRemove={(id) => {
          removed = id
        }}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Remove Severity filter' }))
    expect(removed).toBe('sev')
  })

  it('renders "Clear all" only when there are filters and calls onClear', () => {
    let cleared = 0
    render(
      <SmartFilterBar
        filters={[{ id: 'a', label: 'A', value: '1' }]}
        onClear={() => {
          cleared += 1
        }}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /clear all/i }))
    expect(cleared).toBe(1)
  })

  it('marks the active saved view with aria-pressed and applies views on click', () => {
    let applied = null
    render(
      <SmartFilterBar
        savedViews={[
          { id: 'v1', name: 'Critical KEV' },
          { id: 'v2', name: 'My Assets' },
        ]}
        activeViewId="v1"
        onApplyView={(id) => {
          applied = id
        }}
      />,
    )
    expect(screen.getByRole('button', { name: 'Critical KEV' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    expect(screen.getByRole('button', { name: 'My Assets' })).toHaveAttribute(
      'aria-pressed',
      'false',
    )
    fireEvent.click(screen.getByRole('button', { name: 'My Assets' }))
    expect(applied).toBe('v2')
  })

  it('saves a trimmed view name through the inline input flow', () => {
    let saved = null
    render(
      <SmartFilterBar
        onSaveView={(name) => {
          saved = name
        }}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /save view/i }))
    const input = screen.getByRole('textbox', { name: 'New view name' })
    fireEvent.change(input, { target: { value: '  Weekend Watch  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm view name' }))
    expect(saved).toBe('Weekend Watch')
  })

  it('ignores an empty/whitespace view name on confirm', () => {
    let saved = null
    render(
      <SmartFilterBar
        onSaveView={(name) => {
          saved = name
        }}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /save view/i }))
    const input = screen.getByRole('textbox', { name: 'New view name' })
    fireEvent.change(input, { target: { value: '   ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm view name' }))
    expect(saved).toBeNull()
  })

  it('renders no pills and no "Clear all" when there are no filters', () => {
    render(<SmartFilterBar filters={[]} />)
    expect(screen.queryByRole('button', { name: /clear all/i })).not.toBeInTheDocument()
    // The bar still exposes its group role even when empty.
    expect(screen.getByRole('group', { name: 'Filters' })).toBeInTheDocument()
  })
})
