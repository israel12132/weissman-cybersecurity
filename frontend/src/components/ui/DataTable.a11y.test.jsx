import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'
import React from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import DataTable from './DataTable'

const ch = createColumnHelper()
const columns = [ch.accessor('name', { header: 'Name', enableSorting: false, cell: (c) => c.getValue() })]
const data = [
  { id: '1', name: 'alpha' },
  { id: '2', name: 'bravo' },
]

const rowButtons = (container) => container.querySelectorAll('tr[role="button"]')

afterEach(() => cleanup())

describe('DataTable row keyboard accessibility', () => {
  it('exposes clickable rows as focusable buttons', () => {
    const { container } = render(
      <DataTable columns={columns} data={data} onRowClick={() => {}} animateRows={false} />,
    )
    const rows = rowButtons(container)
    expect(rows.length).toBe(2)
    expect(rows[0]).toHaveAttribute('tabindex', '0')
  })

  it('activates a row on Enter and Space', () => {
    const onRowClick = vi.fn()
    const { container } = render(
      <DataTable columns={columns} data={data} onRowClick={onRowClick} animateRows={false} />,
    )
    const rows = rowButtons(container)
    fireEvent.keyDown(rows[0], { key: 'Enter' })
    fireEvent.keyDown(rows[1], { key: ' ' })
    expect(onRowClick).toHaveBeenCalledTimes(2)
  })

  it('does not make rows interactive without onRowClick', () => {
    const { container } = render(<DataTable columns={columns} data={data} animateRows={false} />)
    expect(rowButtons(container).length).toBe(0)
  })
})
