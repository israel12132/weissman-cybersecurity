import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => {
  const t = (k) => k
  return { useTranslation: () => ({ t }) }
})

vi.mock('./PageShell', () => ({
  default: ({ children, title, actions }) => (
    <div>
      <h1>{title}</h1>
      {actions}
      {children}
    </div>
  ),
}))

vi.mock('../components/engine/ShellScanActions', () => ({
  default: () => <div data-testid="scan-actions" />,
}))

vi.mock('../lib/exportWorkbook', () => ({
  exportWorkbook: vi.fn(),
  tableToWorkbookSpec: vi.fn((s) => s),
}))
vi.mock('../lib/documentExport', () => ({
  exportDocument: vi.fn(),
  tableToDocumentSpec: vi.fn((s) => s),
}))
vi.mock('../lib/exportFindingsCsv', () => ({ downloadCsv: vi.fn() }))

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))

import AiReadiness from './AiReadiness'

const PAYLOAD = {
  providers: [
    {
      provider: 'openai',
      label: 'OpenAI',
      key_env: 'OPENAI_API_KEY',
      configured: true,
      key_fingerprint: 'sha256:deadbeef',
      model: 'gpt-4.1',
      base_url: 'https://api.openai.com/v1',
    },
  ],
  enrichment: [{ id: 'shodan', key_env: 'SHODAN_API_KEY', configured: false, key_fingerprint: '' }],
  active_endpoints: ['ask'],
}

beforeEach(() => {
  apiFetch.mockReset()
  apiFetch.mockResolvedValue(PAYLOAD)
})
afterEach(cleanup)

describe('AiReadiness', () => {
  it('renders live catalog rows through DataTable from parsed apiFetch JSON', async () => {
    render(<AiReadiness />)
    await waitFor(() => expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument())
    expect(apiFetch).toHaveBeenCalledWith('/api/ai/readiness')
    expect(screen.getByText('SHODAN_API_KEY')).toBeInTheDocument()
    expect(screen.getByText('sha256:deadbeef')).toBeInTheDocument()
    expect(screen.getByText('gpt-4.1')).toBeInTheDocument()
    expect(document.querySelector('#ai-readiness-table table')).toBeTruthy()
    const bodyRows = document.querySelectorAll('#ai-readiness-table table tbody tr')
    expect(bodyRows.length).toBe(2)
  })

  it('probes via POST and shows the live result banner', async () => {
    apiFetch.mockImplementation((url, opts) => {
      if (String(url).includes('/probe')) {
        expect(opts?.method).toBe('POST')
        return Promise.resolve({
          ok: true,
          label: 'OpenAI',
          provider: 'openai',
          latency_ms: 42,
          http_status: 200,
        })
      }
      return Promise.resolve(PAYLOAD)
    })
    render(<AiReadiness />)
    await waitFor(() => expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'pages.aiReadiness.probe' }))
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith('/api/ai/readiness/probe', { method: 'POST' }),
    )
    expect(screen.getByText('pages.aiReadiness.probe_ok')).toBeInTheDocument()
  })
})
