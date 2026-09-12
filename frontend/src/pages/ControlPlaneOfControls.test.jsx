import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title, body }) => <div>{title} {body}</div>,
}))
vi.mock('../components/ui/EvidenceNotice', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/ui/ExecutiveWidget', () => ({
  __esModule: true,
  default: ({ label, value }) => <div>{label}:{value}</div>,
}))
vi.mock('../components/ui/Skeleton', () => ({
  SkeletonWidgetGrid: () => <div>loading</div>,
}))

import ControlPlaneOfControls from './ControlPlaneOfControls.jsx'

describe('ControlPlaneOfControls honesty', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint catalog engine count when findings are unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, findings: [], detail: 'store down' })
    render(<ControlPlaneOfControls />)
    expect(await screen.findByText(/pages.controlPlaneOfControls.load_failed/)).toBeTruthy()
    expect(screen.queryByText(/pages.controlPlaneOfControls.kpi_engines:6/)).toBeNull()
  })

  it('counts live engines from findings, not the catalog length', async () => {
    apiFetch.mockResolvedValue({
      findings: [
        { id: 1, source: 'control_plane_of_controls', title: 'a', severity: 'info' },
        { id: 2, source: 'control_plane_of_controls', title: 'b', severity: 'high' },
      ],
    })
    render(<ControlPlaneOfControls />)
    expect(await screen.findByText('pages.controlPlaneOfControls.kpi_engines:1')).toBeTruthy()
    expect(screen.queryByText('pages.controlPlaneOfControls.kpi_engines:6')).toBeNull()
  })
})
