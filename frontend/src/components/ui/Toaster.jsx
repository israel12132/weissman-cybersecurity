import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'

const ToastCtx = createContext(null)

const VARIANT_CONFIG = {
  success: {
    border: 'border-emerald-500/35',
    bg: 'bg-emerald-950/80',
    text: 'text-emerald-100',
    accent: 'text-emerald-400',
    bar: 'bg-emerald-400',
    Icon: CheckCircle2,
    live: 'polite',
  },
  error: {
    border: 'border-rose-500/45',
    bg: 'bg-rose-950/85',
    text: 'text-rose-100',
    accent: 'text-rose-400',
    bar: 'bg-rose-400',
    Icon: XCircle,
    live: 'assertive',
  },
  warning: {
    border: 'border-amber-500/40',
    bg: 'bg-amber-950/80',
    text: 'text-amber-100',
    accent: 'text-amber-400',
    bar: 'bg-amber-400',
    Icon: AlertTriangle,
    live: 'polite',
  },
  info: {
    border: 'border-cyan-500/35',
    bg: 'bg-cyan-950/80',
    text: 'text-cyan-100',
    accent: 'text-cyan-400',
    bar: 'bg-cyan-400',
    Icon: Info,
    live: 'polite',
  },
}

/** Map telemetry severity strings to toast variants. */
export function severityToVariant(severity) {
  if (severity === 'error') return 'error'
  if (severity === 'warning' || severity === 'warn') return 'warning'
  if (severity === 'success') return 'success'
  return 'info'
}

/**
 * Global toast provider. Mount once near the app root.
 * Usage anywhere: `const { toast } = useToast(); toast.success('Saved')`
 * Variants: success | error | warning | info
 */
export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const idRef = useRef(1)

  const push = useCallback((variant, message, opts = {}) => {
    const id = idRef.current++
    const ttl = opts.ttl ?? (variant === 'error' ? 8000 : 4500)
    setItems((prev) => [...prev.slice(-4), {
      id,
      variant,
      message,
      ttl,
      subtitle: opts.subtitle,
      actionLabel: opts.actionLabel,
      onAction: opts.onAction,
    }])
    return id
  }, [])

  const dismiss = useCallback((id) => {
    setItems((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = {
    success: (m, o) => push('success', m, o),
    error: (m, o) => push('error', m, o),
    warning: (m, o) => push('warning', m, o),
    info: (m, o) => push('info', m, o),
    dismiss,
  }

  return (
    <ToastCtx.Provider value={{ toast }}>
      {children}
      <ToastViewport items={items} dismiss={dismiss} />
    </ToastCtx.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastCtx)
  if (!ctx) {
    return {
      toast: {
        success: (m) => console.log('[toast.success]', m),
        error: (m) => console.warn('[toast.error]', m),
        warning: (m) => console.warn('[toast.warn]', m),
        info: (m) => console.log('[toast.info]', m),
        dismiss: () => {},
      },
    }
  }
  return ctx
}

export function ToastViewport({ items, dismiss, className = '' }) {
  if (items.length === 0) return null

  const hasAssertive = items.some((t) => (VARIANT_CONFIG[t.variant] || VARIANT_CONFIG.info).live === 'assertive')

  return (
    <div
      className={`fixed top-4 end-4 z-[10000] flex flex-col gap-2.5 w-full max-w-[22rem] sm:max-w-sm pointer-events-none ${className}`}
      role="region"
      aria-live={hasAssertive ? 'assertive' : 'polite'}
      aria-relevant="additions"
      aria-label="Notifications"
    >
      {items.map((t) => (
        <PremiumToastItem key={t.id} {...t} onDismiss={() => dismiss(t.id)} />
      ))}
    </div>
  )
}

function useDismissTimer({ ttl, onDismiss, paused }) {
  const remainingRef = useRef(ttl)
  const startedAtRef = useRef(Date.now())
  const timerRef = useRef(null)

  useEffect(() => {
    remainingRef.current = ttl
    startedAtRef.current = Date.now()
  }, [ttl])

  useEffect(() => {
    if (ttl <= 0) return undefined

    if (paused) {
      if (timerRef.current) {
        clearTimeout(timerRef.current)
        timerRef.current = null
        remainingRef.current = Math.max(0, remainingRef.current - (Date.now() - startedAtRef.current))
      }
      return undefined
    }

    startedAtRef.current = Date.now()
    timerRef.current = setTimeout(() => {
      onDismiss()
    }, remainingRef.current)

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [ttl, onDismiss, paused])
}

export function PremiumToastItem({
  variant = 'info',
  message,
  subtitle,
  ttl = 4500,
  actionLabel,
  onAction,
  onDismiss,
}) {
  const c = VARIANT_CONFIG[variant] || VARIANT_CONFIG.info
  const { Icon } = c
  const [entered, setEntered] = useState(false)
  const [exiting, setExiting] = useState(false)
  const [paused, setPaused] = useState(false)

  const handleDismiss = useCallback(() => {
    setExiting(true)
    setTimeout(onDismiss, 180)
  }, [onDismiss])

  useDismissTimer({ ttl, onDismiss: handleDismiss, paused })

  useEffect(() => {
    const enterTimer = setTimeout(() => setEntered(true), 16)
    return () => clearTimeout(enterTimer)
  }, [])

  return (
    <div
      role="status"
      aria-atomic="true"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
      className={[
        'pointer-events-auto relative overflow-hidden rounded-xl border shadow-2xl backdrop-blur-md',
        'transition-all ease-out',
        c.border,
        c.bg,
        c.text,
        entered && !exiting ? 'animate-slide-in-end opacity-100 translate-x-0' : '',
        !entered ? 'opacity-0 translate-x-3' : '',
        exiting ? 'opacity-0 translate-x-3 scale-[0.98]' : '',
      ].join(' ')}
      style={{ transitionDuration: 'var(--duration-standard)' }}
    >
      <div className="flex items-start gap-3 px-3.5 py-3 pe-2">
        <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${c.accent}`} aria-hidden="true" strokeWidth={2.25} />
        <div className="flex-1 min-w-0">
          {subtitle && (
            <p className="text-[10px] uppercase tracking-[0.14em] text-white/40 mb-0.5 truncate">
              {subtitle}
            </p>
          )}
          <p className="text-[13px] leading-snug break-words">{message}</p>
          {actionLabel && onAction && (
            <button
              type="button"
              onClick={() => { onAction(); handleDismiss() }}
              className={`mt-2 text-[10px] uppercase tracking-widest px-2 py-1 rounded-md border ${c.border} ${c.accent} hover:bg-black/25 transition-colors`}
              style={{ transitionDuration: 'var(--duration-fast)' }}
            >
              {actionLabel}
            </button>
          )}
        </div>
        <button
          type="button"
          onClick={handleDismiss}
          aria-label="Dismiss notification"
          className="shrink-0 p-1 rounded-md text-white/40 hover:text-white/90 hover:bg-white/8 transition-colors"
          style={{ transitionDuration: 'var(--duration-fast)' }}
        >
          <X className="w-3.5 h-3.5" strokeWidth={2.5} />
        </button>
      </div>
      {ttl > 0 && (
        <div className="absolute inset-x-0 bottom-0 h-[2px] bg-white/5" aria-hidden="true">
          <div
            className={`h-full ${c.bar} animate-toast-progress origin-left`}
            style={{
              animationDuration: `${ttl}ms`,
              animationPlayState: paused ? 'paused' : 'running',
            }}
          />
        </div>
      )}
    </div>
  )
}
