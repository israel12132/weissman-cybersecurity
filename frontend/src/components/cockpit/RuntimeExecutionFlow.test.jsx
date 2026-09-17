import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import RuntimeExecutionFlow from './RuntimeExecutionFlow.jsx'

describe('RuntimeExecutionFlow', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not claim no traces when the traces API is unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, traces: [], detail: 'store down' })
    render(<RuntimeExecutionFlow clientId={3} />)
    expect(await screen.findByTestId('runtime-traces-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitWidgets.runtimeExecutionFlow.noTracesClient')).toBeNull()
  })
})
