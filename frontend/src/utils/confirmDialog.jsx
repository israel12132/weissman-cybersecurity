import { useEffect, useId, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { AlertTriangle, HelpCircle, ShieldAlert, Trash2 } from 'lucide-react'
import Button from '../components/ui/Button'
import useFocusTrap from '../hooks/useFocusTrap'

/**
 * Promise-based confirm / prompt dialogs that match the Command Center's
 * dark-glass aesthetic and replace the native `window.confirm` / `window.prompt`
 * (which are blocking, unstyled, untranslatable, and break the immersive UI).
 *
 * No React provider is required: each call mounts a transient root in a portal
 * host appended to <body> and tears it down when the promise settles. This keeps
 * the helpers usable from any event handler without wiring context into App.
 *
 *   const ok = await confirmDialog({ title, message, confirmLabel, variant })
 *   const name = await promptDialog({ title, label, defaultValue })  // string | null
 *
 * Labels are passed in already-translated (the helper renders outside the i18n
 * tree on purpose), so callers should use t('…') for every visible string.
 */

const VARIANT_STYLES = {
  danger: {
    icon: Trash2,
    iconWrap: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    confirmBtn:
      'bg-rose-500/90 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/40 focus-visible:ring-rose-400/60',
  },
  warning: {
    icon: AlertTriangle,
    iconWrap: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    confirmBtn:
      'bg-amber-500/90 hover:bg-amber-500 text-black shadow-lg shadow-amber-900/40 focus-visible:ring-amber-400/60',
  },
  primary: {
    icon: ShieldAlert,
    iconWrap: 'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30',
    confirmBtn:
      'bg-cyan-500/90 hover:bg-cyan-500 text-black shadow-lg shadow-cyan-900/40 focus-visible:ring-cyan-400/60',
  },
  neutral: {
    icon: HelpCircle,
    iconWrap: 'bg-white/10 text-[var(--text-secondary)] ring-1 ring-white/15',
    confirmBtn:
      'bg-white/90 hover:bg-white text-black shadow-lg focus-visible:ring-white/60',
  },
}

function isRtl() {
  if (typeof document === 'undefined') return false
  const dir = document.documentElement.getAttribute('dir') || document.dir
  return dir === 'rtl'
}

function mountDialog(renderFn) {
  if (typeof document === 'undefined') return
  const host = document.createElement('div')
  host.setAttribute('data-weissman-dialog', '')
  document.body.appendChild(host)
  const root = createRoot(host)

  const prevOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'

  const teardown = () => {
    document.body.style.overflow = prevOverflow
    // Defer the unmount so we never unmount synchronously from within a render/commit.
    setTimeout(() => {
      try {
        root.unmount()
      } catch {
        /* root already gone */
      }
      if (host.parentNode) host.parentNode.removeChild(host)
    }, 0)
  }

  root.render(renderFn(teardown))
}

function DialogShell({
  kind,
  title,
  message,
  confirmLabel,
  cancelLabel,
  variant,
  // prompt-only
  label,
  defaultValue,
  placeholder,
  required,
  inputType,
  multiline,
  settle,
}) {
  const [entered, setEntered] = useState(false)
  const [value, setValue] = useState(defaultValue ?? '')
  const inputRef = useRef(null)
  const confirmRef = useRef(null)
  const dialogRef = useRef(null)
  const settledRef = useRef(false)
  const uid = useId()
  const msgId = `${uid}-msg`
  const inputId = `${uid}-input`
  useFocusTrap(dialogRef, true)
  const rtl = isRtl()
  const style = VARIANT_STYLES[variant] || VARIANT_STYLES.neutral
  const Icon = style.icon

  const finish = (result) => {
    if (settledRef.current) return
    settledRef.current = true
    setEntered(false)
    // allow the exit transition to play before unmount
    setTimeout(() => settle(result), 130)
  }

  const cancel = () => finish(kind === 'prompt' ? null : kind === 'alert' ? undefined : false)
  const confirm = () => {
    if (kind === 'alert') {
      finish(undefined)
      return
    }
    if (kind === 'prompt') {
      const v = value.trim()
      if (required && !v) {
        inputRef.current?.focus()
        return
      }
      finish(value)
    } else {
      finish(true)
    }
  }

  useEffect(() => {
    const id = requestAnimationFrame(() => setEntered(true))
    const focusTimer = setTimeout(() => {
      if (kind === 'prompt') inputRef.current?.focus()
      else confirmRef.current?.focus()
    }, 60)
    return () => {
      cancelAnimationFrame(id)
      clearTimeout(focusTimer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        cancel()
      } else if (e.key === 'Enter' && !(multiline && e.target?.tagName === 'TEXTAREA')) {
        if (e.target?.tagName !== 'TEXTAREA') {
          e.preventDefault()
          confirm()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])

  return (
    <div
      dir={rtl ? 'rtl' : 'ltr'}
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) cancel()
      }}
      className={[
        'fixed inset-0 z-[11000] flex items-center justify-center p-4',
        'bg-black/70 backdrop-blur-sm transition-opacity duration-150',
        entered ? 'opacity-100' : 'opacity-0',
      ].join(' ')}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        aria-describedby={message ? msgId : undefined}
        className={[
          'w-full max-w-md overflow-hidden rounded-2xl border border-white/10',
          'bg-[#0c1018]/95 shadow-2xl shadow-black/60',
          'transition-all duration-150 ease-out',
          entered ? 'opacity-100 scale-100 translate-y-0' : 'opacity-0 scale-95 translate-y-2',
        ].join(' ')}
      >
        <div className="flex items-start gap-4 p-5 pb-4">
          <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${style.iconWrap}`}>
            <Icon className="h-5 w-5" strokeWidth={2} />
          </div>
          <div className="min-w-0 flex-1 pt-0.5">
            <h2 className="text-base font-semibold text-white">{title}</h2>
            {message ? (
              <p id={msgId} className="mt-1 whitespace-pre-line text-sm leading-relaxed text-[var(--text-secondary)]">{message}</p>
            ) : null}
          </div>
        </div>

        {kind === 'prompt' ? (
          <div className="px-5 pb-2">
            {label ? (
              <label htmlFor={inputId} className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
                {label}
              </label>
            ) : null}
            {multiline ? (
              <textarea
                ref={inputRef}
                id={inputId}
                aria-describedby={message ? msgId : undefined}
                value={value}
                rows={4}
                placeholder={placeholder}
                onChange={(e) => setValue(e.target.value)}
                className="w-full resize-y rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white outline-none transition-colors focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/30"
              />
            ) : (
              <input
                ref={inputRef}
                id={inputId}
                aria-describedby={message ? msgId : undefined}
                type={inputType || 'text'}
                value={value}
                placeholder={placeholder}
                onChange={(e) => setValue(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white outline-none transition-colors focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/30"
              />
            )}
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2.5 px-5 py-4">
          {kind !== 'alert' ? (
            <Button variant="unstyled"
              type="button"
              onClick={cancel}
              className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-[var(--text-secondary)] outline-none transition-colors hover:bg-white/10 focus-visible:ring-2 focus-visible:ring-white/30"
            >
              {cancelLabel}
            </Button>
          ) : null}
          <Button variant="unstyled"
            ref={confirmRef}
            type="button"
            onClick={confirm}
            className={`rounded-lg px-4 py-2 text-sm font-semibold outline-none transition-colors focus-visible:ring-2 ${style.confirmBtn}`}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Styled async replacement for window.confirm.
 * @param {string|{title?:string,message?:string,confirmLabel?:string,cancelLabel?:string,variant?:'danger'|'warning'|'primary'|'neutral'}} options
 * @returns {Promise<boolean>}
 */
export function confirmDialog(options = {}) {
  const o = typeof options === 'string' ? { message: options } : options || {}
  const {
    title = 'Are you sure?',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    variant = 'danger',
  } = o
  return new Promise((resolve) => {
    mountDialog((teardown) => (
      <DialogShell
        kind="confirm"
        title={title}
        message={message}
        confirmLabel={confirmLabel}
        cancelLabel={cancelLabel}
        variant={variant}
        settle={(r) => {
          teardown()
          resolve(Boolean(r))
        }}
      />
    ))
  })
}

/**
 * Styled async replacement for window.prompt. Resolves to the entered string,
 * or null if the user cancels.
 * @param {string|{title?:string,message?:string,label?:string,defaultValue?:string,placeholder?:string,confirmLabel?:string,cancelLabel?:string,required?:boolean,inputType?:string,multiline?:boolean}} options
 * @returns {Promise<string|null>}
 */
export function promptDialog(options = {}) {
  const o = typeof options === 'string' ? { message: options } : options || {}
  const {
    title = 'Input required',
    message = '',
    label = '',
    defaultValue = '',
    placeholder = '',
    confirmLabel = 'OK',
    cancelLabel = 'Cancel',
    required = false,
    inputType = 'text',
    multiline = false,
  } = o
  return new Promise((resolve) => {
    mountDialog((teardown) => (
      <DialogShell
        kind="prompt"
        title={title}
        message={message}
        label={label}
        defaultValue={defaultValue}
        placeholder={placeholder}
        confirmLabel={confirmLabel}
        cancelLabel={cancelLabel}
        required={required}
        inputType={inputType}
        multiline={multiline}
        variant="primary"
        settle={(r) => {
          teardown()
          resolve(r)
        }}
      />
    ))
  })
}

/**
 * Styled async replacement for window.alert — a single-acknowledge modal. Useful
 * for must-read notices outside React components (where the toast hook is not
 * available). Prefer the `useToast()` toast for transient in-component feedback.
 * @param {string|{title?:string,message?:string,confirmLabel?:string,variant?:'danger'|'warning'|'primary'|'neutral'}} options
 * @returns {Promise<void>}
 */
export function alertDialog(options = {}) {
  const o = typeof options === 'string' ? { message: options } : options || {}
  const {
    title = 'Notice',
    message = '',
    confirmLabel = 'OK',
    variant = 'primary',
  } = o
  return new Promise((resolve) => {
    mountDialog((teardown) => (
      <DialogShell
        kind="alert"
        title={title}
        message={message}
        confirmLabel={confirmLabel}
        cancelLabel=""
        variant={variant}
        settle={() => {
          teardown()
          resolve()
        }}
      />
    ))
  })
}
