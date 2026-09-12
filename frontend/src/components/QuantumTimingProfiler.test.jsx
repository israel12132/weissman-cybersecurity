import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))
vi.mock('./ui/StandaloneLabShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('./ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
vi.mock('recharts', () => ({
  LineChart: () => null,
  Line: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  Legend: () => null,
  ResponsiveContainer: ({ children }) => <div>{children}</div>,
  ReferenceLine: () => null,
}))
const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import QuantumTimingProfiler from './QuantumTimingProfiler.jsx'

describe('QuantumTimingProfiler', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not treat a store-down clients API as a missing client, and does not paint a zero waveform', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, clients: [], detail: 'store down' })
    render(<QuantumTimingProfiler />)
    expect(await screen.findByTestId('timing-profiler-unavailable')).toBeTruthy()
    expect(screen.queryByText('0 μs')).toBeNull()
  })
})
