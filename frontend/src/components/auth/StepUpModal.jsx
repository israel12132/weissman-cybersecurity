import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck } from 'lucide-react'
import { Modal } from '../ui/Modal'
import Button from '../ui/Button'
import Input from '../ui/Input'
import { api } from '../../utils/apiFetch'

const NS = 'components.stepUpModal'
const CODE_LENGTH = 6

/**
 * Step-up (fresh re-auth) challenge dialog.
 *
 * Prompts for the current 6-digit TOTP, exchanges it at `POST /api/auth/step-up` for a
 * short-lived step-up token, and hands the token back via `onVerified(token, expiresIn)`.
 * It is a controlled dialog: pair it with `useStepUpAction`, which owns the token cache and
 * retries the gated action once the token is issued.
 *
 * @param {boolean} open
 * @param {() => void} onClose        dismiss (also called on ESC / overlay when not busy)
 * @param {(token: string, expiresIn: number) => void} onVerified
 */
export default function StepUpModal({ open, onClose, onVerified }) {
  const { t } = useTranslation()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const inputRef = useRef(null)

  // Reset transient state each time the dialog opens, then focus the code field.
  useEffect(() => {
    if (!open) return
    setCode('')
    setErr('')
    setBusy(false)
    const id = window.setTimeout(() => inputRef.current?.focus(), 0)
    return () => window.clearTimeout(id)
  }, [open])

  const canClose = !busy
  const handleClose = useCallback(() => {
    if (canClose) onClose?.()
  }, [canClose, onClose])

  const submit = useCallback(
    async (e) => {
      e?.preventDefault?.()
      if (busy || code.length !== CODE_LENGTH) return
      setBusy(true)
      setErr('')
      try {
        const d = await api.post('/api/auth/step-up', { totp_code: code })
        if (!d?.ok || !d.step_up_token) {
          throw new Error(d?.detail || t(`${NS}.errors.failed`))
        }
        onVerified?.(d.step_up_token, d.expires_in)
      } catch (e2) {
        // utils/apiFetch throws with .status (+ parsed .body) on a non-2xx response.
        if (e2?.status === 400) setErr(t(`${NS}.errors.mfa_required`))
        else if (e2?.status === 401) setErr(t(`${NS}.errors.invalid_code`))
        else if (e2?.status === 429) setErr(t(`${NS}.errors.locked`))
        else if (e2?.status === 503) setErr(t(`${NS}.errors.degraded`))
        else setErr(e2?.body?.detail || e2?.message || t(`${NS}.errors.failed`))
        setBusy(false)
      }
    },
    [busy, code, onVerified, t],
  )

  return (
    <Modal
      open={open}
      onClose={handleClose}
      size="sm"
      title={t(`${NS}.title`)}
      description={t(`${NS}.description`)}
      closeOnOverlay={canClose}
      closeOnEsc={canClose}
      footer={
        <>
          <Button variant="ghost" onClick={handleClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            onClick={submit}
            loading={busy}
            disabled={code.length !== CODE_LENGTH}
          >
            {t(`${NS}.verify`)}
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <div className="flex items-center gap-2 text-text-tertiary">
          <ShieldCheck className="size-4 text-accent-cyan" aria-hidden="true" />
          <span className="text-xs leading-relaxed">{t(`${NS}.hint`)}</span>
        </div>
        <Input
          ref={inputRef}
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={CODE_LENGTH}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, CODE_LENGTH))}
          placeholder={t(`${NS}.code_placeholder`)}
          aria-label={t(`${NS}.code_label`)}
          error={err || undefined}
          disabled={busy}
          className="text-center font-mono tracking-[0.4em]"
        />
      </form>
    </Modal>
  )
}
