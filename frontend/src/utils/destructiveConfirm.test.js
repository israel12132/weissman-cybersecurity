import { describe, it, expect, beforeEach } from 'vitest'
import { dualControlHeaders, persistDualControlTokens, loadDestructiveConfirmToken, loadDualApproveToken } from './destructiveConfirm'

describe('dualControlHeaders', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('sends both dual-control headers when tokens are provided', () => {
    const h = dualControlHeaders('confirm-secret', 'dual-secret')
    expect(h['X-Weissman-Destructive-Confirm']).toBe('confirm-secret')
    expect(h['X-Weissman-Dual-Approve']).toBe('dual-secret')
  })

  it('falls back to session storage when arguments are empty', () => {
    persistDualControlTokens('from-session', 'dual-session', true)
    expect(loadDestructiveConfirmToken()).toBe('from-session')
    expect(loadDualApproveToken()).toBe('dual-session')
    const h = dualControlHeaders('', '')
    expect(h['X-Weissman-Destructive-Confirm']).toBe('from-session')
    expect(h['X-Weissman-Dual-Approve']).toBe('dual-session')
  })

  it('does not persist when remember is false', () => {
    persistDualControlTokens('a', 'b', false)
    expect(loadDestructiveConfirmToken()).toBe('')
    expect(loadDualApproveToken()).toBe('')
  })
})
