import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import FindingVerifyButton, { findingVerifyId } from './FindingLiveVerify.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, vars) => {
      if (!vars) return k
      return `${k}:${JSON.stringify(vars)}`
    },
  }),
}))

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../utils/apiFetch', () => ({ apiFetch }))

afterEach(() => {
  cleanup()
})

describe('findingVerifyId', () => {
  it('prefers numeric raw_id and strips VLN- from display ids', () => {
    expect(findingVerifyId({ raw_id: 42, id: 'VLN-42' })).toBe('42')
    expect(findingVerifyId({ id: 'VLN-7' })).toBe('7')
    expect(findingVerifyId({ finding_id: 'sha-abc' })).toBe('sha-abc')
    expect(findingVerifyId({})).toBe('')
    expect(findingVerifyId(null)).toBe('')
  })
})

describe('FindingVerifyButton', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })

  it('posts /api/findings/:id/verify and renders the live verdict', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      verdict: 'LIKELY_VALID',
      confidence: 0.7,
      checks: [{ id: 'reachability', label: 'Reach', passed: true, detail: 'HTTP 200' }],
      verified_at: '2026-08-25T00:00:00Z',
    })
    const onVerified = vi.fn()
    render(
      <FindingVerifyButton
        finding={{ raw_id: 11, id: 'VLN-11', title: 'XSS' }}
        onVerified={onVerified}
        variant="primary"
      />,
    )
    fireEvent.click(screen.getByText('findings.liveVerify.button'))
    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(1))
    expect(apiFetch.mock.calls[0][0]).toBe('/api/findings/11/verify')
    expect(apiFetch.mock.calls[0][1].body).toEqual({ deep: false })
    await waitFor(() =>
      expect(screen.getAllByText(/findings\.liveVerify\.verdict_LIKELY_VALID/).length).toBeGreaterThan(0),
    )
    expect(screen.getByText('HTTP 200')).toBeInTheDocument()
    expect(onVerified).toHaveBeenCalled()
  })

  it('deep scan sends deep:true and shows the engine rescan check', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      verdict: 'CONFIRMED',
      confidence: 0.9,
      reproducible: true,
      rescan_message: 'xss_engine: 1 finding',
      rescan_finding_count: 1,
      checks: [
        { id: 'engine_rescan', label: 'Engine re-scan reproduction', passed: true, detail: 'reproduced' },
      ],
    })
    render(<FindingVerifyButton finding={{ raw_id: 11 }} variant="primary" />)
    fireEvent.click(screen.getByText('findings.liveVerify.button_deep'))
    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(1))
    expect(apiFetch.mock.calls[0][1].body).toEqual({ deep: true })
    await waitFor(() => expect(screen.getByText('findings.liveVerify.reproduced')).toBeInTheDocument())
    expect(screen.getByText('Engine re-scan reproduction')).toBeInTheDocument()
  })

  it('surfaces API errors instead of a blank panel', async () => {
    apiFetch.mockRejectedValue(new Error('finding not found'))
    render(<FindingVerifyButton finding={{ raw_id: 99 }} variant="primary" />)
    fireEvent.click(screen.getByText('findings.liveVerify.button'))
    await waitFor(() => expect(screen.getByText('finding not found')).toBeInTheDocument())
  })
})
