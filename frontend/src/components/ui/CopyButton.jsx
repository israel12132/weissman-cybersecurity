import React, { useCallback, useState } from 'react'
import { Check, Copy } from 'lucide-react'

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

  const copy = useCallback(() => {
    const text = value != null ? String(value) : ''
    if (!text.trim()) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [value])

  const iconSize = size === 'md' ? 'w-3.5 h-3.5' : 'w-3 h-3'
  const pad = size === 'md' ? 'p-1.5' : 'p-1'

  return (
    <button
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
    </button>
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
