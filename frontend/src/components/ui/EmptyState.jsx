import React from 'react'

/**
 * Empty-state card. Use whenever a list / table has nothing to show.
 *
 * Props:
 *  - icon:    optional emoji or React node displayed at the top
 *  - title:   short heading
 *  - body:    longer explanation
 *  - cta:     { label, onClick } primary action
 *  - secondary: { label, href|onClick } optional secondary link
 */
export default function EmptyState({
  icon = '∅',
  title,
  body,
  cta,
  secondary,
  className = '',
}) {
  return (
    <div
      className={`flex flex-col items-center text-center py-12 px-6 rounded-2xl border border-white/5 bg-black/20 ${className}`}
      role="status"
    >
      <div className="text-4xl mb-3 opacity-60" aria-hidden="true">{icon}</div>
      {title && <h3 className="text-base font-semibold text-white/85">{title}</h3>}
      {body && <p className="text-[13px] text-white/45 mt-2 max-w-md leading-relaxed">{body}</p>}
      {(cta || secondary) && (
        <div className="flex gap-3 mt-5 flex-wrap justify-center">
          {cta && (
            <button
              type="button"
              onClick={cta.onClick}
              className="px-4 py-2 rounded-lg text-sm font-mono border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25"
            >
              {cta.label}
            </button>
          )}
          {secondary && (secondary.href ? (
            <a
              href={secondary.href}
              className="px-4 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/30"
            >
              {secondary.label}
            </a>
          ) : (
            <button
              type="button"
              onClick={secondary.onClick}
              className="px-4 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/30"
            >
              {secondary.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
