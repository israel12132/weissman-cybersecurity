import { describe, it, expect, afterEach } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import DataTable from './DataTable.jsx'

afterEach(cleanup)

const columns = [
  { accessorKey: 'id', header: 'ID' },
  { accessorKey: 'name', header: 'Name' },
]
const makeData = (n) => Array.from({ length: n }, (_, i) => ({ id: i, name: `Row ${i}` }))

describe('DataTable virtualization', () => {
  it('renders every row when not virtualized (opt-in, default off)', () => {
    const { container } = render(
      <DataTable columns={columns} data={makeData(300)} hidePagination animateRows={false} />,
    )
    expect(container.querySelectorAll('tbody tr[data-row-id]').length).toBe(300)
    // No spacer rows in the non-virtualized path.
    expect(container.querySelector('tbody tr[aria-hidden="true"]')).toBeNull()
  })

  it('windows rows and adds a spacer row when virtualized', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={makeData(300)}
        hidePagination
        animateRows={false}
        virtualized
        rowHeight={20}
        overscan={5}
      />,
    )
    const dataRows = container.querySelectorAll('tbody tr[data-row-id]')
    // Only a window is rendered — far fewer nodes than the full 300 rows.
    expect(dataRows.length).toBeGreaterThan(0)
    expect(dataRows.length).toBeLessThan(300)
    // A spacer row preserves scrollbar geometry for the un-rendered tail.
    const spacer = container.querySelector('tbody tr[aria-hidden="true"] td')
    expect(spacer).not.toBeNull()
    expect(spacer.style.height).toMatch(/px$/)
  })

  it('does not virtualize when sub-rows are enabled (auto-disabled)', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={makeData(300)}
        hidePagination
        animateRows={false}
        virtualized
        rowHeight={20}
        renderSubRow={(row) => <div>detail {row.id}</div>}
      />,
    )
    // Expandable tables fall back to rendering all rows (no windowing/spacers).
    expect(container.querySelectorAll('tbody tr[data-row-id]').length).toBe(300)
    expect(container.querySelector('tbody tr[aria-hidden="true"]')).toBeNull()
  })
})
