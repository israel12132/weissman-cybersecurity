import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import Button from './Button'

/** Legacy fallback for non-secure origins where navigator.clipboard is unavailable. */
function fallbackCopy(text) {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

/**
 * Copy-to-clipboard control for monospace / technical fields.
 *
 * Props:
 *  - value: text to copy
 *  - label: accessible label (default "Copy")
 *  - size: 'sm' | 'md'
 *  - className
 */
export default function CopyButton({ value, label = 'Copy', size = 'sm', className = '' }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current) }, [])

  const markCopied = useCallback(() => {
    setCopied(true)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), 2000)
  }, [])

  const copy = useCallback(() => {
    const text = value != null ? String(value) : ''
    if (!text.trim()) return
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text)
        .then(markCopied)
        .catch(() => { if (fallbackCopy(text)) markCopied() })
    } else if (fallbackCopy(text)) {
      markCopied()
    }
  }, [value, markCopied])

  const iconSize = size === 'md' ? 'w-3.5 h-3.5' : 'w-3 h-3'
  const pad = size === 'md' ? 'p-1.5' : 'p-1'

  return (
    <Button variant="unstyled"
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        copy()
      }}
      className={`inline-flex items-center gap-1 rounded border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-muted)] hover:text-cyan-300/90 hover:border-cyan-500/30 transition-colors ${pad} ${className}`}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? (
        <Check className={`${iconSize} text-emerald-400`} strokeWidth={2.5} />
      ) : (
        <Copy className={iconSize} strokeWidth={2} />
      )}
      {size === 'md' && (
        <span className="text-[10px] font-mono">{copied ? 'Copied' : label}</span>
      )}
    </Button>
  )
}

/**
 * Monospace field with inline copy button.
 */
export function CopyableField({ label, value, mono = true, className = '' }) {
  if (value == null || value === '') return null
  const text = String(value)

  return (
    <div className={`flex items-start gap-2 min-w-0 ${className}`}>
      {label && (
        <span className="shrink-0 text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide pt-1">
          {label}
        </span>
      )}
      <code
        className={`flex-1 min-w-0 text-[12px] text-[var(--text-secondary)] break-all ltr-only ${
          mono ? 'font-mono' : ''
        }`}
      >
        {text}
      </code>
      <CopyButton value={text} size="sm" />
    </div>
  )
}
