import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (typeof d === 'string') return d
      if (d && typeof d === 'object') {
        return `${k}:${Object.values(d).join(',')}`
      }
      return k
    },
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))
vi.mock('../context/AuthContext', () => ({
  useAuth: () => ({ isCeo: false, isLoading: false }),
}))
vi.mock('../hooks/useVisiblePolling', () => ({ useVisiblePolling: () => {} }))
vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (findings) => ({ filteredFindings: findings }),
}))
vi.mock('../components/ui/DataTable', () => ({
  __esModule: true,
  default: ({ data, onRowClick }) => (
    <div>
      {(data || []).map((row) => (
        <button
          key={row.id || row.job_id}
          type="button"
          onClick={() => onRowClick({ original: row })}
        >
          {row.id || row.job_id}
        </button>
      ))}
    </div>
  ),
}))
vi.mock('../components/ui/CopyButton', () => ({
  __esModule: true,
  default: () => null,
  CopyableField: ({ label, value }) => (
    <div>
      {label}: {String(value)}
    </div>
  ),
}))

import JobsDashboard from './JobsDashboard.jsx'

describe('JobsDashboard', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders live Redis/worker census from GET /api/jobs/diagnostics', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/api/jobs/diagnostics')) {
        return Promise.resolve({
          ok: true,
          redis: { configured: true, inspect_ok: true },
          workers: { alive: 1, inspected: 1, ids: ['w1'] },
          pending_no_envelope: 2,
          stuck_reason: [{ id: 'job-stuck', status: 'running', stuck_reason: 'redis lease missing' }],
        })
      }
      return Promise.resolve({
        jobs: [
          {
            id: 'job-stuck',
            kind: 'command_center_engine',
            status: 'running',
            operator_state: 'stuck',
            target: 'example.test',
          },
        ],
        total: 1,
      })
    })

    render(
      <MemoryRouter>
        <JobsDashboard />
      </MemoryRouter>,
    )

    expect(await screen.findByTestId('jobs-census-redis')).toHaveTextContent('pages.jobsDashboard.census_redis_ok')
    expect(screen.getByTestId('jobs-census-workers')).toHaveTextContent('1/1')
    expect(screen.getByTestId('jobs-census-pending')).toHaveTextContent('2')
    expect(screen.getByTestId('jobs-census-stuck')).toHaveTextContent('1')
    expect(apiFetch).toHaveBeenCalledWith('/api/jobs/diagnostics')
    expect(screen.getByTestId('jobs-tile-stuck')).toHaveTextContent('1')

    fireEvent.click(screen.getByText('job-stuck'))
    await waitFor(() => {
      expect(screen.getByText(/redis lease missing/)).toBeInTheDocument()
    })
  })

  it('fails visibly when diagnostics is missing instead of inventing a healthy census', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/api/jobs/diagnostics')) {
        return Promise.reject(new Error('diagnostics down'))
      }
      return Promise.resolve({ jobs: [], total: 0 })
    })

    render(
      <MemoryRouter>
        <JobsDashboard />
      </MemoryRouter>,
    )

    expect(await screen.findByRole('alert')).toHaveTextContent('pages.jobsDashboard.census_unavailable')
    expect(screen.getByTestId('jobs-census-redis')).toHaveTextContent('—')
    expect(screen.queryByText('pages.jobsDashboard.census_redis_ok')).toBeNull()
  })
})
