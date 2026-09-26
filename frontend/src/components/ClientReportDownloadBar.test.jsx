import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'

// i18n: identity translator + a switchable UI language so both label sets are exercised.
const i18nState = vi.hoisted(() => ({ language: 'en' }))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: i18nState.language } }),
}))
const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))
const lib = vi.hoisted(() => ({
  downloadClientPdf: vi.fn(),
  downloadClientXlsx: vi.fn(),
  openClientReportView: vi.fn(),
}))
vi.mock('../lib/downloadClientReport', () => lib)

import ClientReportDownloadBar from './ClientReportDownloadBar'

beforeEach(() => {
  i18nState.language = 'en'
  lib.downloadClientPdf.mockReset().mockResolvedValue({})
  lib.downloadClientXlsx.mockReset().mockResolvedValue({})
  lib.openClientReportView.mockReset().mockResolvedValue({})
})
afterEach(() => cleanup())

describe('ClientReportDownloadBar', () => {
  it('renders nothing without a client', () => {
    const { container } = render(<ClientReportDownloadBar clientId={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('opens the technical report in the UI language and the board report as executive', async () => {
    render(<ClientReportDownloadBar clientId={42} />)
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.report_view' }))
    await waitFor(() =>
      expect(lib.openClientReportView).toHaveBeenCalledWith(apiFetch, 42, 'en', 'technical'),
    )
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.report_board' }))
    await waitFor(() =>
      expect(lib.openClientReportView).toHaveBeenCalledWith(apiFetch, 42, 'en', 'executive'),
    )
  })

  it('offers the OTHER language as a switch: Hebrew UI → English report, English UI → Hebrew report', async () => {
    const { unmount } = render(<ClientReportDownloadBar clientId={42} />)
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.report_view_hebrew' }))
    await waitFor(() =>
      expect(lib.openClientReportView).toHaveBeenCalledWith(apiFetch, 42, 'he', 'technical'),
    )
    unmount()

    i18nState.language = 'he-IL'
    render(<ClientReportDownloadBar clientId={42} />)
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.report_view_english' }))
    await waitFor(() =>
      expect(lib.openClientReportView).toHaveBeenCalledWith(apiFetch, 42, 'en', 'technical'),
    )
    // The primary button follows the UI language.
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.report_view' }))
    await waitFor(() =>
      expect(lib.openClientReportView).toHaveBeenCalledWith(apiFetch, 42, 'he', 'technical'),
    )
  })

  it('keeps the legacy PDF / Excel downloads wired', async () => {
    render(<ClientReportDownloadBar clientId={9} />)
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.download_pdf' }))
    await waitFor(() => expect(lib.downloadClientPdf).toHaveBeenCalledWith(apiFetch, 9))
    fireEvent.click(screen.getByRole('button', { name: 'client_detail.download_xlsx' }))
    await waitFor(() => expect(lib.downloadClientXlsx).toHaveBeenCalledWith(apiFetch, 9))
  })

  it('shows the busy label while a report opens, disables the bar, and surfaces failures', async () => {
    let release
    lib.openClientReportView.mockImplementation(() => new Promise((r) => (release = r)))
    render(<ClientReportDownloadBar clientId={42} />)
    const view = screen.getByRole('button', { name: 'client_detail.report_view' })
    fireEvent.click(view)
    await waitFor(() => expect(view).toHaveTextContent('client_detail.report_opening'))
    screen.getAllByRole('button').forEach((b) => expect(b).toBeDisabled())
    release({})
    await waitFor(() => expect(view).toHaveTextContent('client_detail.report_view'))
    expect(screen.queryByRole('alert')).toBeNull()

    lib.openClientReportView.mockRejectedValueOnce(new Error('popup_blocked'))
    fireEvent.click(view)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('popup_blocked'))
    // A failure with no message falls back to the translated generic error.
    lib.openClientReportView.mockRejectedValueOnce({})
    fireEvent.click(view)
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('client_detail.export_server_failed'),
    )
  })
})
