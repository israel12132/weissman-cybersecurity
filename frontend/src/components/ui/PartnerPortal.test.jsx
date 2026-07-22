import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import PartnerPortal from './PartnerPortal.jsx'

afterEach(cleanup)

const tenants = [
  { id: 'acme', name: 'Acme Corp', clients: 12, openFindings: 43, posture: 82, status: 'active' },
  { id: 'globex', name: 'Globex', clients: 5, openFindings: 120, posture: 54, status: 'pending' },
]

describe('PartnerPortal', () => {
  it('renders a card per tenant with stats', () => {
    render(<PartnerPortal tenants={tenants} />)
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('Globex')).toBeInTheDocument()
    expect(screen.getByText('82')).toBeInTheDocument()
  })

  it('selects a tenant on click', () => {
    const onSelectTenant = vi.fn()
    render(<PartnerPortal tenants={tenants} onSelectTenant={onSelectTenant} />)
    fireEvent.click(screen.getByText('Globex'))
    expect(onSelectTenant).toHaveBeenCalledWith(tenants[1])
  })

  it('marks the active tenant', () => {
    const { container } = render(<PartnerPortal tenants={tenants} activeTenantId="acme" />)
    expect(container.querySelector('[aria-current="true"]')).toHaveTextContent('Acme Corp')
  })

  it('shows an empty message', () => {
    render(<PartnerPortal tenants={[]} emptyMessage="No tenants yet" />)
    expect(screen.getByText('No tenants yet')).toBeInTheDocument()
  })
})
