import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, waitFor } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../../hooks/useVisiblePolling', () => ({
  useVisiblePolling: () => {},
}))

import ScanStatusIndicator from './ScanStatusIndicator.jsx'

describe('ScanStatusIndicator', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })

  it('treats running_async_jobs as active even when scanning_active is false', async () => {
    apiFetch.mockResolvedValue({
      scanning_active: false,
      scan_in_progress: false,
      running_async_jobs: 2,
    })
    const { container } = render(<ScanStatusIndicator />)
    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/scan/status'))
    await waitFor(() => expect(container.querySelector('[role="status"]')).toBeTruthy())
  })
})
