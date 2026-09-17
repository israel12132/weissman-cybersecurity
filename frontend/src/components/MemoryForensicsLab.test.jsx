import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('./ui/StandaloneLabShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../lib/sseStream', () => ({ openSseStream: () => ({ close() {} }) }))
vi.mock('react-window', () => ({
  List: () => null,
}))

import MemoryForensicsLab from './MemoryForensicsLab.jsx'

describe('MemoryForensicsLab', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint an empty-success lab when PoE findings fail to load', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/poe-findings')) {
        return Promise.resolve({ ok: false, unavailable: true, findings: [], detail: 'store down' })
      }
      if (url === '/api/clients') return Promise.resolve([])
      return Promise.resolve({})
    })
    render(<MemoryForensicsLab />)
    expect(await screen.findByTestId('memory-lab-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.tools.memoryForensicsLab.no_findings')).toBeNull()
  })
})
