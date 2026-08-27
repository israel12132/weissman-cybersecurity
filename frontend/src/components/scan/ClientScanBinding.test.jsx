import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ClientScanBinding, { BoundClientScanField } from './ClientScanBinding.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const mockCtx = vi.hoisted(() => ({ current: null }))
vi.mock('../../context/ClientContext', () => ({
  useClientOptional: () => mockCtx.current,
}))

const clients = [
  { id: 7, name: 'Acme Corp', domains: '["acme.example"]' },
  { id: 9, name: 'Other Co', domains: '["other.test"]' },
]

describe('ClientScanBinding', () => {
  beforeEach(() => {
    mockCtx.current = null
  })

  it('hides the picker when the session is client-locked', () => {
    render(
      <ClientScanBinding
        clients={clients}
        selectedClientId={7}
        locked
        onChange={() => {}}
      />,
    )
    expect(screen.getByTestId('client-scan-binding-locked')).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('https://acme.example')).toBeInTheDocument()
  })

  it('shows a picker for staff/owner sessions', () => {
    const calls = []
    render(
      <ClientScanBinding
        clients={clients}
        selectedClientId={null}
        locked={false}
        onChange={(v) => calls.push(v)}
      />,
    )
    const select = screen.getByRole('combobox')
    expect(select).toBeInTheDocument()
    fireEvent.change(select, { target: { value: '9' } })
    expect(calls).toEqual(['9'])
  })

  it('BoundClientScanField never renders a picker for portal sessions and syncs assigned id', () => {
    mockCtx.current = {
      clientScopeLocked: true,
      selectedClientId: 7,
      clients,
      selectedClient: clients[0],
    }
    const calls = []
    render(
      <BoundClientScanField
        clients={clients}
        selectedClientId={null}
        onChange={(v) => calls.push(v)}
      />,
    )
    expect(screen.getByTestId('client-scan-binding-locked')).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(calls).toEqual([7])
  })
})
