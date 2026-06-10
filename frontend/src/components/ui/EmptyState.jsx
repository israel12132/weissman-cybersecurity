import React from 'react'
import {
  AlertTriangle,
  FileSearch,
  Inbox,
  Radar,
  SearchX,
  Shield,
  ShieldOff,
} from 'lucide-react'

const ICON_MAP = {
  inbox: Inbox,
  shield: Shield,
  'shield-off': ShieldOff,
  search: FileSearch,
  'search-x': SearchX,
  radar: Radar,
  alert: AlertTriangle,
}

/**
 * Premium empty state — icon + title + description + optional CTA.
 * No illustrations; lucide icons only.
 *
 * Props:
 *  - icon: lucide key (inbox, shield, search, …) or custom React node
 *  - title, body (alias: description)
 *  - cta: { label, onClick }
 *  - secondary: { label, href | onClick }
 *  - compact: smaller padding
 *  - className
 */
export default function EmptyState({
  icon = 'inbox',
  title,
  body,
  description,
  cta,
  secondary,
  compact = false,
  className = '',
}) {
  const copy = body ?? description
  const IconComponent = typeof icon === 'string' ? ICON_MAP[icon] ?? Inbox : null

  return (
    <div
      className={`flex flex-col items-center text-center rounded-2xl border border-white/[0.07] bg-[var(--card-bg)]/40 backdrop-blur-sm ${
        compact ? 'py-8 px-5' : 'py-14 px-8'
      } ${className}`}
      role="status"
    >
      <div
        className={`mb-4 flex items-center justify-center rounded-xl border border-white/10 bg-white/[0.03] ${
          compact ? 'w-11 h-11' : 'w-14 h-14'
        }`}
        aria-hidden="true"
      >
        {IconComponent ? (
          <IconComponent
            className={`${compact ? 'w-5 h-5' : 'w-6 h-6'} text-[var(--accent)]`}
            strokeWidth={1.75}
          />
        ) : (
          icon
        )}
      </div>

      {title && (
        <h3 className={`font-semibold text-[var(--accent-strong)] ${compact ? 'text-sm' : 'text-base'}`}>
          {title}
        </h3>
      )}
      {copy && (
        <p
          className={`text-[var(--text-muted)] mt-2 max-w-md leading-relaxed ${
            compact ? 'text-xs' : 'text-[13px]'
          }`}
        >
          {copy}
        </p>
      )}

      {(cta || secondary) && (
        <div className="flex gap-3 mt-6 flex-wrap justify-center">
          {cta && (
            <button
              type="button"
              onClick={cta.onClick}
              className="px-4 py-2 rounded-lg text-sm font-mono border border-cyan-500/35 bg-cyan-500/10 text-cyan-200/90 hover:bg-cyan-500/20 transition-colors"
            >
              {cta.label}
            </button>
          )}
          {secondary &&
            (secondary.href ? (
              <a
                href={secondary.href}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/25 transition-colors"
              >
                {secondary.label}
              </a>
            ) : (
              <button
                type="button"
                onClick={secondary.onClick}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/25 transition-colors"
              >
                {secondary.label}
              </button>
            ))}
        </div>
      )}
    </div>
  )
}
