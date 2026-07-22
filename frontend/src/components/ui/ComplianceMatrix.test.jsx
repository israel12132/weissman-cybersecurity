import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import ComplianceMatrix from './ComplianceMatrix.jsx'

afterEach(cleanup)

const frameworks = [
  { id: 'iso', label: 'ISO 27001' },
  { id: 'soc2', label: 'SOC 2' },
  { id: 'nist', label: 'NIST' },
]
const controls = [
  { id: 'ac', label: 'Access control', status: { iso: 'covered', soc2: 'partial', nist: 'gap' } },
  { id: 'enc', label: 'Encryption', status: { iso: 'covered', soc2: 'covered', nist: 'na' } },
]

describe('ComplianceMatrix', () => {
  it('renders a column per framework and a row per control', () => {
    render(<ComplianceMatrix frameworks={frameworks} controls={controls} />)
    expect(screen.getByRole('columnheader', { name: 'ISO 27001' })).toBeInTheDocument()
    expect(screen.getByRole('rowheader', { name: 'Access control' })).toBeInTheDocument()
    expect(screen.getByRole('rowheader', { name: 'Encryption' })).toBeInTheDocument()
  })

  it('labels each cell with its coverage status', () => {
    render(<ComplianceMatrix frameworks={frameworks} controls={controls} />)
    expect(screen.getByLabelText(/Access control · ISO 27001: Covered/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Access control · NIST: Gap/)).toBeInTheDocument()
  })

  it('fires onCellClick with the control, framework id, and status', () => {
    const onCellClick = vi.fn()
    render(<ComplianceMatrix frameworks={frameworks} controls={controls} onCellClick={onCellClick} />)
    fireEvent.click(screen.getByRole('button', { name: /Encryption · SOC 2: Covered/ }))
    expect(onCellClick).toHaveBeenCalledWith(controls[1], 'soc2', 'covered')
  })

  it('renders a legend of statuses', () => {
    render(<ComplianceMatrix frameworks={frameworks} controls={controls} />)
    expect(screen.getByText('Partial')).toBeInTheDocument()
    expect(screen.getByText('Gap')).toBeInTheDocument()
  })
})
