import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

const toast = { success: vi.fn(), error: vi.fn() }
vi.mock('../ui/Toaster', () => ({
  useToast: () => ({ toast }),
}))

vi.mock('../ui/Switch', () => ({
  __esModule: true,
  default: ({ label, checked, onChange, disabled }) => (
    <label>
      {label}
      <input
        type="checkbox"
        role="switch"
        aria-label={label}
        checked={checked}
        disabled={disabled}
        onChange={onChange}
      />
    </label>
  ),
}))

vi.mock('../ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title }) => <div>{title}</div>,
}))

import CrownJewelBoard from './CrownJewelBoard.jsx'

describe('CrownJewelBoard', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    toast.success.mockReset()
    toast.error.mockReset()
  })
  afterEach(cleanup)

  it('PATCHes crown_jewel then asks the parent to recompute', async () => {
    apiFetch.mockImplementation(async (url, opts) => {
      if (String(url).includes('/risk-graph') && !opts?.method) {
        return {
          nodes: [
            { id: 42, label: 'payroll-db', node_type: 'db', risk_score: 9, crown_jewel: false, internet_exposed: true },
          ],
        }
      }
      if (String(url).includes('/flags')) {
        return { ok: true, id: 42, client_id: 7 }
      }
      return {}
    })
    const onChanged = vi.fn()
    render(<CrownJewelBoard clientId={7} onChanged={onChanged} />)
    expect(await screen.findByText('payroll-db')).toBeTruthy()
    const jewelSwitch = screen.getAllByRole('switch')[1]
    fireEvent.click(jewelSwitch)
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/42/flags',
        expect.objectContaining({
          method: 'PATCH',
          body: { crown_jewel: true },
        }),
      )
    })
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('reports live jewel inventory without inventing jewels', async () => {
    const onInventory = vi.fn()
    apiFetch.mockResolvedValue({
      nodes: [
        { id: 1, label: 'edge', crown_jewel: false, internet_exposed: true },
      ],
    })
    render(<CrownJewelBoard clientId={7} onInventory={onInventory} />)
    expect(await screen.findByText('edge')).toBeTruthy()
    await waitFor(() =>
      expect(onInventory).toHaveBeenCalledWith(
        expect.objectContaining({ total: 1, jewels: 0, exposed: 1 }),
      ),
    )
  })

  it('shows an empty graph without inventing jewels', async () => {
    apiFetch.mockResolvedValue({ nodes: [], edges: [] })
    render(<CrownJewelBoard clientId={7} />)
    expect(await screen.findByText('pages.attackPaths.jewel_empty_title')).toBeTruthy()
  })
})
