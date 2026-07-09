import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { createColumnHelper } from '@tanstack/react-table'
import DataTable from './DataTable'

const ch = createColumnHelper()
const columns = [
  ch.accessor('name', { header: 'Name', cell: (c) => c.getValue() }),
  ch.accessor('kind', { header: 'Kind', cell: (c) => c.getValue() }),
]
const data = [
  { id: '1', name: 'alpha', kind: 'ip' },
  { id: '2', name: 'bravo', kind: 'domain' },
]

afterEach(() => cleanup())

describe('DataTable expandable sub-rows', () => {
  it('does not inject an expander column when renderSubRow is absent', () => {
    const { container } = render(<DataTable columns={columns} data={data} animateRows={false} />)
    // Two accessor headers only, no expander cell.
    expect(container.querySelectorAll('thead th').length).toBe(2)
    expect(container.querySelector('button[aria-label="Expand row"]')).toBeNull()
  })

  it('renders an expander column and toggles the detail row', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={data}
        animateRows={false}
        renderSubRow={(orig) => <div data-testid="detail">detail:{orig.name}</div>}
      />,
    )
    // Expander column prepended → 3 header cells.
    expect(container.querySelectorAll('thead th').length).toBe(3)
    // Collapsed: no detail rendered.
    expect(screen.queryByTestId('detail')).toBeNull()

    const expanders = container.querySelectorAll('button[aria-label="Expand row"]')
    expect(expanders.length).toBe(2)

    fireEvent.click(expanders[0])
    const detail = screen.getByTestId('detail')
    expect(detail.textContent).toBe('detail:alpha')

    // Button now advertises collapse and aria-expanded flips.
    const collapse = container.querySelector('button[aria-label="Collapse row"]')
    expect(collapse).toBeTruthy()
    expect(collapse.getAttribute('aria-expanded')).toBe('true')

    // Toggle back closed.
    fireEvent.click(collapse)
    expect(screen.queryByTestId('detail')).toBeNull()
  })

  it('honours getRowCanExpand to hide the expander on specific rows', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={data}
        animateRows={false}
        getRowCanExpand={(row) => row.original.kind === 'ip'}
        renderSubRow={(orig) => <div>detail:{orig.name}</div>}
      />,
    )
    // Only the ip row (alpha) gets an expander button.
    expect(container.querySelectorAll('button[aria-label="Expand row"]').length).toBe(1)
  })

  it('expander click does not trigger onRowClick', () => {
    let clicks = 0
    const { container } = render(
      <DataTable
        columns={columns}
        data={data}
        animateRows={false}
        onRowClick={() => { clicks += 1 }}
        renderSubRow={(orig) => <div data-testid="detail">detail:{orig.name}</div>}
      />,
    )
    fireEvent.click(container.querySelector('button[aria-label="Expand row"]'))
    expect(clicks).toBe(0)
    expect(screen.getByTestId('detail')).toBeTruthy()
  })

  it('hidePagination hides the bar and renders every row', () => {
    const many = Array.from({ length: 60 }, (_, i) => ({ id: String(i), name: `n${i}`, kind: 'ip' }))
    const { container } = render(
      <DataTable columns={columns} data={many} animateRows={false} hidePagination />,
    )
    // No "Rows:" pagination control.
    expect(container.textContent).not.toContain('Rows:')
    // All 60 rows render (no client-side page slice to 25).
    expect(container.querySelectorAll('tbody tr').length).toBe(60)
  })

  it('enableSelection prepends a checkbox column and emits selected originals', () => {
    const onSel = vi.fn()
    const { container } = render(
      <DataTable columns={columns} data={data} animateRows={false} enableSelection onSelectionChange={onSel} />,
    )
    // header select-all + 2 row checkboxes = 3 checkboxes; +1 header column.
    const boxes = container.querySelectorAll('input[type="checkbox"]')
    expect(boxes.length).toBe(3)
    expect(container.querySelectorAll('thead th').length).toBe(3)

    // Select the first row → callback fires with that original.
    const rowBoxes = container.querySelectorAll('tbody input[type="checkbox"]')
    fireEvent.click(rowBoxes[0])
    const last = onSel.mock.calls[onSel.mock.calls.length - 1]
    expect(last[0].map((o) => o.name)).toEqual(['alpha'])
    expect(last[1]).toEqual(['1'])
  })

  it('select-all header selects every row', () => {
    const onSel = vi.fn()
    const { container } = render(
      <DataTable columns={columns} data={data} animateRows={false} enableSelection onSelectionChange={onSel} />,
    )
    const headerBox = container.querySelector('thead input[type="checkbox"]')
    fireEvent.click(headerBox)
    const last = onSel.mock.calls[onSel.mock.calls.length - 1]
    expect(last[0].length).toBe(2)
  })

  it('selectionResetSignal clears the current selection', () => {
    const onSel = vi.fn()
    const { container, rerender } = render(
      <DataTable columns={columns} data={data} animateRows={false} enableSelection onSelectionChange={onSel} selectionResetSignal={0} />,
    )
    fireEvent.click(container.querySelector('tbody input[type="checkbox"]'))
    expect(onSel.mock.calls.at(-1)[0].length).toBe(1)
    rerender(
      <DataTable columns={columns} data={data} animateRows={false} enableSelection onSelectionChange={onSel} selectionResetSignal={1} />,
    )
    expect(onSel.mock.calls.at(-1)[0].length).toBe(0)
  })

  it('does not add a checkbox column when selection is off', () => {
    const { container } = render(<DataTable columns={columns} data={data} animateRows={false} />)
    expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(0)
  })

  it('detail row spans the full column count', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={data}
        animateRows={false}
        renderSubRow={(orig) => <span>detail:{orig.name}</span>}
      />,
    )
    fireEvent.click(container.querySelector('button[aria-label="Expand row"]'))
    const detailCell = within(container).getByText(/detail:alpha/).closest('td')
    // expander + name + kind = 3 columns.
    expect(detailCell.getAttribute('colspan')).toBe('3')
  })
})
