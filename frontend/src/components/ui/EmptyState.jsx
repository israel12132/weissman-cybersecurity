import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  BarChart3,
  Bot,
  Building2,
  DollarSign,
  FileSearch,
  FileText,
  Inbox,
  Link2,
  List,
  Network,
  Radar,
  SearchX,
  Shield,
  ShieldOff,
  Target,
} from 'lucide-react'
import Button from './Button'

const ICON_MAP = {
  inbox: Inbox,
  shield: Shield,
  'shield-off': ShieldOff,
  search: FileSearch,
  'search-x': SearchX,
  radar: Radar,
  alert: AlertTriangle,
  building: Building2,
  chart: BarChart3,
  file: FileText,
  target: Target,
  bot: Bot,
  link: Link2,
  dollar: DollarSign,
  network: Network,
  list: List,
}

/**
 * Premium empty state — icon + title + description + optional CTA.
 * Prefer a lucide key from ICON_MAP (inbox, shield, search, chart, …).
 *
 * Props:
 *  - icon: lucide key (inbox, shield, search, …), a custom React node, or an
 *    emoji/text glyph string. Unknown strings render verbatim in the badge
 *    rather than silently falling back to the inbox icon.
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
  // Known lucide key → rendered as an icon component. A string that is not a
  // known key (e.g. an emoji) is rendered verbatim; a React node is rendered
  // as-is. Only an undefined/null icon defaults to the inbox glyph.
  const IconComponent = typeof icon === 'string' ? ICON_MAP[icon] : null
  const glyphText = typeof icon === 'string' && !IconComponent ? icon : null

  return (
    <div
      className={`flex flex-col items-center text-center rounded-2xl border border-[var(--border-subtle)] bg-[var(--card-bg)]/40 backdrop-blur-sm ${
        compact ? 'py-8 px-5' : 'py-14 px-8'
      } ${className}`}
      role="status"
    >
      <div
        className={`mb-4 flex items-center justify-center rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] ${
          compact ? 'w-11 h-11' : 'w-14 h-14'
        }`}
        aria-hidden="true"
      >
        {IconComponent ? (
          <IconComponent
            className={`${compact ? 'w-5 h-5' : 'w-6 h-6'} text-[var(--accent)]`}
            strokeWidth={1.75}
          />
        ) : glyphText ? (
          <span className={`${compact ? 'text-lg' : 'text-xl'} leading-none`}>{glyphText}</span>
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
          {cta &&
            (cta.to ? (
              <Link
                to={cta.to}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-cyan-500/35 bg-cyan-500/10 text-cyan-200/90 hover:bg-cyan-500/20 transition-colors"
              >
                {cta.label}
              </Link>
            ) : (
              <Button variant="unstyled"
                type="button"
                onClick={cta.onClick}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-cyan-500/35 bg-cyan-500/10 text-cyan-200/90 hover:bg-cyan-500/20 transition-colors"
              >
                {cta.label}
              </Button>
            ))}
          {secondary &&
            (secondary.to ? (
              <Link
                to={secondary.to}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
              >
                {secondary.label}
              </Link>
            ) : secondary.href ? (
              <a
                href={secondary.href}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
              >
                {secondary.label}
              </a>
            ) : (
              <Button variant="unstyled"
                type="button"
                onClick={secondary.onClick}
                className="px-4 py-2 rounded-lg text-sm font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
              >
                {secondary.label}
              </Button>
            ))}
        </div>
      )}
    </div>
  )
}
