import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  Link: ({ children }) => <a>{children}</a>,
}))
vi.mock('./PageShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/engine/ShellScanActions', () => ({ default: () => null }))
vi.mock('../components/ui/EmptyState', () => ({
  default: ({ title, body }) => (
    <div>
      <span>{title}</span>
      <span>{body}</span>
    </div>
  ),
}))
vi.mock('../components/ui/Skeleton', () => ({
  SkeletonWidgetGrid: () => null,
  SkeletonTable: () => null,
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (list) => ({
    exportCsv: vi.fn(),
    filteredFindings: list,
  }),
}))
vi.mock('../components/ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
vi.mock('recharts', () => ({
  LineChart: () => null,
  Line: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }) => <div>{children}</div>,
  BarChart: () => null,
  Bar: () => null,
}))
const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({
  api: { get: (...args) => apiGet(...args) },
}))

import BaselineAndDrift from './BaselineAndDrift.jsx'

describe('BaselineAndDrift', () => {
  beforeEach(() => apiGet.mockReset())
  afterEach(cleanup)

  it('does not paint empty-drift theater when baseline APIs are unavailable', async () => {
    apiGet.mockResolvedValue({
      ok: false,
      unavailable: true,
      data: [],
      anomalies: [],
      total_assets: 0,
      baseline_rows: 0,
      detail: 'store down',
    })
    render(<BaselineAndDrift />)
    expect(await screen.findByTestId('baseline-unavailable')).toBeTruthy()
    expect(screen.queryByText('pages.baselineAndDrift.no_drift_data')).toBeNull()
    expect(screen.queryByText('pages.baselineAndDrift.no_anomaly_volume')).toBeNull()
    expect(screen.queryByText('pages.baselineAndDrift.no_anomalies_title')).toBeNull()
    expect(screen.queryByText('pages.baselineAndDrift.no_baseline_title')).toBeNull()
  })
})
