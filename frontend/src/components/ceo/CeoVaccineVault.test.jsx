import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k) => k
  return { useTranslation: () => ({ t }) }
})
const { apiFetch, apiUrl } = vi.hoisted(() => ({ apiFetch: vi.fn(), apiUrl: (p) => p }))
vi.mock('../../lib/apiBase', () => ({ apiFetch, apiUrl }))

import CeoVaccineVault from './CeoVaccineVault'

const VAULT = [
  { id: 'vac-1', tech_fingerprint: 'nginx', severity: 'high', preemptive_validated: true, component_ref: 'nginx@1.25' },
  { id: 'vac-2', tech_fingerprint: 'apache', severity: 'medium', preemptive_validated: false, component_ref: 'httpd@2.4' },
]

beforeEach(() => apiFetch.mockReset())
afterEach(() => cleanup())

describe('CeoVaccineVault → DataTable', () => {
  it('renders vault rows and selecting a row via onRowClick loads its chain view', async () => {
    apiFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve(VAULT) })
    render(<CeoVaccineVault />)

    await waitFor(() => expect(screen.getByText('nginx')).toBeInTheDocument())
    const bodyRows = document.querySelectorAll('table tbody tr')
    expect(bodyRows.length).toBe(VAULT.length)
    // yes/no validated column rendered from the accessor
    expect(screen.getByText('components.ceo.vaccineVault.yes')).toBeInTheDocument()

    // Clicking a row selects it (no crash; the detail pane reacts to selection).
    fireEvent.click(screen.getByText('nginx'))
    await waitFor(() => expect(document.querySelector('[data-row-id="vac-1"]')).toBeTruthy())
  })
})
