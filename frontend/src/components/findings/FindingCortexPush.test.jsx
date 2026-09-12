import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import FindingCortexPush, { canPushFindingToCortex } from './FindingCortexPush.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled, ...rest }) => (
    <button type="button" onClick={onClick} disabled={disabled} {...rest}>{children}</button>
  ),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({ apiFetch: (...args) => apiFetch(...args) }))

describe('canPushFindingToCortex', () => {
  it('allows confirmed live verdicts', () => {
    expect(canPushFindingToCortex({ live_verdict: 'CONFIRMED' })).toBe(true)
    expect(canPushFindingToCortex({ live_verification: { verdict: 'LIKELY_VALID' } })).toBe(true)
  })

  it('blocks noise', () => {
    expect(canPushFindingToCortex({ live_verdict: 'NOISE' })).toBe(false)
    expect(canPushFindingToCortex({ live_verdict: 'FALSE_POSITIVE' })).toBe(false)
  })

  it('allows proof artifacts without a verdict', () => {
    expect(canPushFindingToCortex({ raw: { oast_callback: 'https://oast.example/x' } })).toBe(true)
    expect(canPushFindingToCortex({ raw: { raw: { oast_callback: 'https://oast.example/x' } } })).toBe(true)
  })

  it('rejects attestation-only rows', () => {
    expect(canPushFindingToCortex({ raw: { attestation: { receipt: 'abc' } } })).toBe(false)
  })

  it('blocks workflow false-positives even with proof', () => {
    expect(
      canPushFindingToCortex({
        live_verdict: 'CONFIRMED',
        status: 'FALSE_POSITIVE',
      }),
    ).toBe(false)
  })

  it('does not treat attestation as proof', () => {
    expect(canPushFindingToCortex({ raw: { attestation: { receipt: 'wzat1:x' } } })).toBe(false)
  })

  it('rejects empty findings', () => {
    expect(canPushFindingToCortex({})).toBe(false)
    expect(canPushFindingToCortex(null)).toBe(false)
  })
})

describe('FindingCortexPush', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('does not POST when the finding is noise', () => {
    render(<FindingCortexPush finding={{ raw_id: 9, live_verdict: 'NOISE' }} />)
    fireEvent.click(screen.getByTestId('push-cortex'))
    expect(apiFetch).not.toHaveBeenCalled()
  })

  it('POSTs /api/findings/:id/push-cortex for a confirmed finding', async () => {
    apiFetch.mockResolvedValue({ ok: true, xdr_had_matching_alert: false })
    render(<FindingCortexPush finding={{ raw_id: 42, live_verdict: 'CONFIRMED' }} />)
    fireEvent.click(screen.getByTestId('push-cortex'))
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/findings/42/push-cortex',
        expect.objectContaining({ method: 'POST', body: { dry_run: false } }),
      )
    })
    expect(screen.getByText('findings.cortexPush.blind_spot')).toBeTruthy()
  })

  it('surfaces a live 409 when Cortex is not configured', async () => {
    apiFetch.mockRejectedValue(new Error('cortex_xsiam integration is not configured'))
    render(<FindingCortexPush finding={{ raw_id: 7, live_verdict: 'CONFIRMED' }} />)
    fireEvent.click(screen.getByTestId('push-cortex'))
    expect(await screen.findByRole('alert')).toHaveTextContent(/not configured/)
  })
})
