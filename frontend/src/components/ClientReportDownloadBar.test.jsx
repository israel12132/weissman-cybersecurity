import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const { downloadClientReport } = vi.hoisted(() => ({ downloadClientReport: vi.fn() }))
vi.mock('../lib/downloadClientReport', () => ({ downloadClientReport }))

import ClientReportDownloadBar from './ClientReportDownloadBar'

beforeEach(() => {
  downloadClientReport.mockReset()
  downloadClientReport.mockResolvedValue('Weissman_Assessment.pdf')
})
afterEach(() => cleanup())

describe('ClientReportDownloadBar', () => {
  it('offers PDF and Excel downloads for a client', async () => {
    render(<ClientReportDownloadBar clientId={12} />)
    fireEvent.click(screen.getByText('components.reportView.download_pdf'))
    await waitFor(() =>
      expect(downloadClientReport).toHaveBeenCalledWith(12, 'pdf', 'en'),
    )
    fireEvent.click(screen.getByText('components.reportView.download_xlsx'))
    await waitFor(() =>
      expect(downloadClientReport).toHaveBeenCalledWith(12, 'xlsx', 'en'),
    )
  })

  it('renders nothing without a client', () => {
    const { container } = render(<ClientReportDownloadBar />)
    expect(container.firstChild).toBeNull()
  })
})
