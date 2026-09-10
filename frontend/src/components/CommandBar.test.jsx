import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

const launchEngineScan = vi.fn()
vi.mock('../lib/launchEngineScan', () => ({
  launchEngineScan: (...args) => launchEngineScan(...args),
}))

import CommandBar from './CommandBar.jsx'

describe('SOC CommandBar (intel-map)', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    launchEngineScan.mockReset()
    apiFetch.mockResolvedValue([{ id: 1, name: 'augury', domains: ['https://www.augury.com'] }])
  })
  afterEach(cleanup)

  it('auto-selects the only client and does not POST run-all on the first click', async () => {
    render(<CommandBar />)
    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/clients'))
    expect(screen.getByTestId('intel-map-command-bar')).toBeInTheDocument()
    const scanAll = screen.getByRole('button', { name: 'components.commandBar.scan_all' })
    fireEvent.click(scanAll)
    expect(apiFetch.mock.calls.some((c) => c[0] === '/api/scan/run-all')).toBe(false)
    expect(scanAll).toHaveTextContent('components.commandBar.scan_all_confirm')
  })

  it('POSTs run-all only after the confirm click', async () => {
    apiFetch.mockImplementation(async (url) => {
      if (url === '/api/clients') return [{ id: 1, name: 'augury', domains: ['https://www.augury.com'] }]
      if (url === '/api/scan/run-all') return { job_id: 'job-1', status: 'started' }
      throw new Error(`unexpected ${url}`)
    })
    render(<CommandBar />)
    await waitFor(() => expect(screen.getByDisplayValue(/augury.com/)).toBeInTheDocument())
    const scanAll = screen.getByRole('button', { name: 'components.commandBar.scan_all' })
    fireEvent.click(scanAll)
    fireEvent.click(screen.getByRole('button', { name: 'components.commandBar.scan_all' }))
    await waitFor(() => {
      expect(apiFetch.mock.calls.some((c) => c[0] === '/api/scan/run-all' && c[1]?.method === 'POST')).toBe(true)
    })
  })
})
