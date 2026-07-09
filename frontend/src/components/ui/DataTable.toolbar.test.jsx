import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
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
  { id: '3', name: 'charlie', kind: 'ip' },
]

const rowButtons = (c) => c.querySelectorAll('tbody tr')

afterEach(() => cleanup())

describe('DataTable toolbar', () => {
  it('renders no toolbar by default', () => {
    const { container } = render(<DataTable columns={columns} data={data} animateRows={false} />)
    expect(container.querySelector('input[type="search"]')).toBeNull()
  })

  it('filters rows via the built-in global search', () => {
    const { container } = render(
      <DataTable columns={columns} data={data} animateRows={false} searchable />,
    )
    expect(rowButtons(container).length).toBe(3)
    const input = container.querySelector('input[type="search"]')
    fireEvent.change(input, { target: { value: 'domain' } })
    // only the row with kind=domain (bravo) matches
    expect(rowButtons(container).length).toBe(1)
  })

  it('renders an export button when exportable', () => {
    render(<DataTable columns={columns} data={data} animateRows={false} exportable />)
    expect(screen.getByText('CSV')).toBeTruthy()
  })

  it('renders a column toggle when columnToggle', () => {
    render(<DataTable columns={columns} data={data} animateRows={false} columnToggle />)
    expect(screen.getByText('Columns')).toBeTruthy()
  })
})
