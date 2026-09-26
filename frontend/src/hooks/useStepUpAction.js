import { useCallback, useRef, useState } from 'react'
import { getStepUpToken, setStepUpToken, STEP_UP_HEADER } from '../lib/stepUpToken'

/**
 * True when a thrown apiFetch error is the backend's step-up gate denial
 * (403 + `error_code: "step_up_required"` — see crate::auth_stepup). utils/apiFetch attaches
 * the parsed JSON body to `err.body` on a non-2xx response, so we can read the machine code
 * rather than string-matching the human `detail`.
 * @param {any} err
 * @returns {boolean}
 */
export function isStepUpRequired(err) {
  return err?.status === 403 && err?.body?.error_code === 'step_up_required'
}

/** Error thrown into the caller's `runWithStepUp` promise when the operator dismisses the modal. */
export const STEP_UP_CANCELLED = 'step_up_cancelled'

/**
 * Drive a privileged API action through the step-up (fresh re-auth) gate.
 *
 * Usage in a component:
 *   const { runWithStepUp, stepUpModalProps } = useStepUpAction()
 *   ...
 *   await runWithStepUp((headers) =>
 *     apiFetch('/api/admin/users/42', { method: 'PATCH', headers, body }))
 *   ...
 *   <StepUpModal {...stepUpModalProps} />
 *
 * `runWithStepUp(run)` calls `run(headers)` with a headers object that carries a cached
 * step-up token when one is still valid. If the backend answers 403 `step_up_required`
 * (enforcement on and no fresh assertion), the returned promise stays pending, the modal
 * opens, and on a successful TOTP verification `run` is retried once with the fresh
 * `X-Weissman-StepUp` header — so the caller sees a single resolved/rejected promise and
 * never has to know a challenge happened. Dismissing the modal rejects with an error whose
 * `.code === STEP_UP_CANCELLED`, which callers treat as "no-op", not a failure to surface.
 */
export function useStepUpAction() {
  const [open, setOpen] = useState(false)
  // Holds the deferred retry while the modal is open: { run, resolve, reject }.
  const pendingRef = useRef(null)

  const runWithStepUp = useCallback((run) => {
    const firstAttempt = () => {
      const token = getStepUpToken()
      const headers = token ? { [STEP_UP_HEADER]: token } : {}
      return run(headers)
    }
    return Promise.resolve()
      .then(firstAttempt)
      .catch((err) => {
        if (!isStepUpRequired(err)) throw err
        // Fresh re-auth needed: defer this action until the modal produces a token.
        return new Promise((resolve, reject) => {
          pendingRef.current = { run, resolve, reject }
          setOpen(true)
        })
      })
  }, [])

  // Modal succeeded: cache the token and retry the deferred action exactly once.
  const handleVerified = useCallback((token, expiresIn) => {
    setStepUpToken(token, expiresIn)
    setOpen(false)
    const pending = pendingRef.current
    pendingRef.current = null
    if (!pending) return
    Promise.resolve()
      .then(() => pending.run({ [STEP_UP_HEADER]: token }))
      .then(pending.resolve, pending.reject)
  }, [])

  // Modal dismissed: reject the deferred action with a recognizable cancellation.
  const handleClose = useCallback(() => {
    setOpen(false)
    const pending = pendingRef.current
    pendingRef.current = null
    if (!pending) return
    const cancelled = new Error(STEP_UP_CANCELLED)
    cancelled.code = STEP_UP_CANCELLED
    pending.reject(cancelled)
  }, [])

  return {
    runWithStepUp,
    stepUpModalProps: { open, onClose: handleClose, onVerified: handleVerified },
  }
}

export default useStepUpAction
