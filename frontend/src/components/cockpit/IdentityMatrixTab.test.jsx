import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k) => k
  return { useTranslation: () => ({ t }) }
})
vi.mock('framer-motion', () => ({ motion: new Proxy({}, { get: () => (p) => <div {...p} /> }) }))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 'c1', selectedClient: { id: 'c1' } }),
}))
vi.mock('../../context/WarRoomContext', () => ({
  useWarRoom: () => ({ lastHarvestedToken: null, setLastHarvestedToken: vi.fn() }),
}))
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../utils/apiFetch', () => ({ apiFetch }))

import IdentityMatrixTab from './IdentityMatrixTab'

const CONTEXTS = [
  { id: 'x1', role_name: 'admin', privilege_order: 1, token_type: 'jwt', token_masked: 'ey***' },
  { id: 'x2', role_name: 'analyst', privilege_order: 2, token_type: 'session', token_masked: 'se***' },
]

beforeEach(() => {
  apiFetch.mockReset()
  apiFetch.mockImplementation((url, opts) => {
    const u = String(url)
    if (opts?.method === 'DELETE') return Promise.resolve({})
    if (u.includes('/identity-contexts')) return Promise.resolve({ contexts: CONTEXTS })
    return Promise.resolve({})
  })
})
afterEach(() => cleanup())

describe('IdentityMatrixTab → DataTable', () => {
  it('renders identity contexts and the delete action fires a DELETE', async () => {
    render(<IdentityMatrixTab />)
    await waitFor(() => expect(screen.getByText('admin')).toBeInTheDocument())
    const bodyRows = document.querySelectorAll('table tbody tr')
    expect(bodyRows.length).toBe(CONTEXTS.length)

    const deleteButtons = screen.getAllByLabelText('components.cockpitTabs.identityMatrix.delete')
    expect(deleteButtons.length).toBe(CONTEXTS.length)
    fireEvent.click(deleteButtons[0])
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/clients/c1/identity-contexts/x1',
        expect.objectContaining({ method: 'DELETE' }),
      ),
    )
  })
})
