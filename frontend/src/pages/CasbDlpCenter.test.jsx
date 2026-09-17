import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

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
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))
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
vi.mock('../components/ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))

import CasbDlpCenter from './CasbDlpCenter.jsx'

describe('CasbDlpCenter honesty', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint a clean SaaS posture when findings are unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, findings: [], detail: 'store down' })
    render(<CasbDlpCenter />)
    expect(await screen.findByTestId('casb-dlp-unavailable')).toBeTruthy()
    expect(screen.queryByText('pages.casbDlpCenter.empty_title')).toBeNull()
    expect(screen.queryByText(/pages.casbDlpCenter.kpi_findings/)).toBeNull()
  })

  it('counts live engines from findings, not the catalog length', async () => {
    apiFetch.mockResolvedValue({
      findings: [
        { id: 1, source: 'casb_saas_posture', title: 'a', severity: 'info' },
        { id: 2, source: 'casb_saas_posture', title: 'b', severity: 'info' },
      ],
    })
    render(<CasbDlpCenter />)
    expect(await screen.findByText('pages.casbDlpCenter.kpi_engines:1')).toBeTruthy()
    expect(screen.queryByText('pages.casbDlpCenter.kpi_engines:4')).toBeNull()
  })

  it('dashes the engines KPI when the live findings list is empty', async () => {
    apiFetch.mockResolvedValue({ findings: [] })
    render(<CasbDlpCenter />)
    expect(await screen.findByText('pages.casbDlpCenter.kpi_engines:—')).toBeTruthy()
    expect(screen.queryByText('pages.casbDlpCenter.kpi_engines:0')).toBeNull()
    expect(screen.queryByText('pages.casbDlpCenter.kpi_engines:4')).toBeNull()
  })

  it('does not apply findings after the in-flight load is aborted', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'CasbDlpCenter.jsx'), 'utf8')
    expect(src).toMatch(/if \(ac\.signal\.aborted\) return/)
  })
})
