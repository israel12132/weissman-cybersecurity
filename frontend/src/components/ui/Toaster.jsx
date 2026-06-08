import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'

const ToastCtx = createContext(null)

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
    setItems((prev) => [...prev, { id, variant, message, ttl, actionLabel: opts.actionLabel, onAction: opts.onAction }])
    if (ttl > 0) {
      setTimeout(() => setItems((prev) => prev.filter((t) => t.id !== id)), ttl)
    }
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
  // Soft-fail when used outside the provider so a missing wrapper doesn't crash the page.
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

function ToastViewport({ items, dismiss }) {
  if (items.length === 0) return null
  return (
    <div
      className="fixed top-4 end-4 z-[10000] flex flex-col gap-2 max-w-sm pointer-events-none"
      role="region"
      aria-live="polite"
      aria-label="Notifications"
    >
      {items.map((t) => (
        <ToastItem key={t.id} {...t} onDismiss={() => dismiss(t.id)} />
      ))}
    </div>
  )
}

const COLORS = {
  success: { border: 'border-emerald-500/40', bg: 'bg-emerald-500/10', text: 'text-emerald-200', dot: 'bg-emerald-400' },
  error:   { border: 'border-rose-500/50',    bg: 'bg-rose-500/10',    text: 'text-rose-200',    dot: 'bg-rose-400' },
  warning: { border: 'border-amber-500/40',   bg: 'bg-amber-500/10',   text: 'text-amber-200',   dot: 'bg-amber-400' },
  info:    { border: 'border-cyan-500/40',    bg: 'bg-cyan-500/10',    text: 'text-cyan-200',    dot: 'bg-cyan-400' },
}

function ToastItem({ variant, message, actionLabel, onAction, onDismiss }) {
  const c = COLORS[variant] || COLORS.info
  const [entered, setEntered] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setEntered(true), 10)
    return () => clearTimeout(t)
  }, [])
  return (
    <div
      role="status"
      className={`pointer-events-auto rounded-xl border ${c.border} ${c.bg} ${c.text} px-3 py-3 text-sm font-mono shadow-2xl backdrop-blur transition-all duration-200 ${
        entered ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-2'
      }`}
    >
      <div className="flex items-start gap-2">
        <span className={`mt-1 w-2 h-2 rounded-full ${c.dot} shrink-0`} aria-hidden="true" />
        <p className="flex-1 break-words leading-relaxed">{message}</p>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="opacity-60 hover:opacity-100 -mt-1 -me-1 px-1 text-base leading-none"
        >
          ×
        </button>
      </div>
      {actionLabel && onAction && (
        <div className="mt-2 ms-4">
          <button
            type="button"
            onClick={() => { onAction(); onDismiss() }}
            className={`text-[11px] uppercase tracking-widest px-2 py-1 rounded border ${c.border} ${c.text} hover:bg-black/30`}
          >
            {actionLabel}
          </button>
        </div>
      )}
    </div>
  )
}
