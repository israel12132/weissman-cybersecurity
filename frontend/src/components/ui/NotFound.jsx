import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Compass, LayoutDashboard, Radar, ShieldAlert } from 'lucide-react'
import Logo from '../Logo'

const QUICK_LINKS = [
  { to: '/', label: 'Dashboard', desc: 'Command Center overview', Icon: LayoutDashboard },
  { to: '/findings', label: 'Findings', desc: 'Vulnerability findings hub', Icon: ShieldAlert },
  { to: '/engines', label: 'Engines', desc: 'Scan engine matrix', Icon: Radar },
]

/**
 * Branded 404 page. Shown whenever the router lands on an unknown route OR a route's
 * Suspense + ErrorBoundary determines the chunk doesn't exist.
 */
export default function NotFound() {
  const { t } = useTranslation()
  const location = useLocation()

  return (
    <div
      className="min-h-[100dvh] flex flex-col items-center justify-center p-6 sm:p-10 text-slate-100 animate-fade-in"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <div className="w-full max-w-lg">
        <div className="text-center mb-8">
          <div className="mx-auto mb-5 opacity-90 inline-block">
            <Logo size={48} />
          </div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[10px] font-mono tracking-widest text-[var(--text-muted)] uppercase mb-4">
            <Compass className="w-3 h-3 text-cyan-400/70" aria-hidden="true" />
            Route not found
          </div>
          <div className="text-[5.5rem] sm:text-7xl font-bold font-mono leading-none text-transparent bg-clip-text bg-gradient-to-b from-cyan-400/50 to-cyan-900/20 mb-3 select-none">
            404
          </div>
          <h1 className="text-xl font-semibold text-[var(--text-primary)] mb-2">
            {t('errors.unknown_route')}
          </h1>
          <p className="text-sm text-[var(--text-tertiary)] font-mono break-all">
            <code className="text-cyan-300/75">{location.pathname}</code>
          </p>
        </div>

        <p className="text-[13px] text-[var(--text-muted)] text-center mb-8 leading-relaxed max-w-md mx-auto">
          The page you requested doesn&apos;t exist or was moved. Use the links below to return to an active module.
        </p>

        <nav aria-label="Quick navigation" className="grid gap-2.5 mb-8">
          {QUICK_LINKS.map(({ to, label, desc, Icon }) => (
            <Link
              key={to}
              to={to}
              className="group flex items-center gap-3.5 px-4 py-3.5 rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] hover:bg-cyan-500/[0.06] hover:border-cyan-500/30 transition-all"
              style={{ transitionDuration: 'var(--duration-standard)' }}
            >
              <span className="flex items-center justify-center w-9 h-9 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] group-hover:border-cyan-500/25 group-hover:bg-cyan-500/10 transition-colors" style={{ transitionDuration: 'var(--duration-fast)' }}>
                <Icon className="w-4 h-4 text-cyan-400/80" strokeWidth={2} aria-hidden="true" />
              </span>
              <span className="flex-1 min-w-0 text-start">
                <span className="block text-sm font-medium text-[var(--text-primary)] group-hover:text-cyan-100 transition-colors" style={{ transitionDuration: 'var(--duration-fast)' }}>
                  {label}
                </span>
                <span className="block text-[11px] text-[var(--text-muted)] mt-0.5">{desc}</span>
              </span>
              <ArrowLeft className="w-4 h-4 text-[var(--text-disabled)] group-hover:text-cyan-400/60 rotate-180 transition-colors shrink-0" style={{ transitionDuration: 'var(--duration-fast)' }} aria-hidden="true" />
            </Link>
          ))}
        </nav>

        <div className="flex gap-3 justify-center flex-wrap">
          <button
            type="button"
            onClick={() => window.history.back()}
            className="px-4 py-2 rounded-lg text-sm font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors"
            style={{ transitionDuration: 'var(--duration-fast)' }}
          >
            ← Go back
          </button>
          <Link
            to="/status"
            className="px-4 py-2 rounded-lg text-sm font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
            style={{ transitionDuration: 'var(--duration-fast)' }}
          >
            System status
          </Link>
        </div>
      </div>
    </div>
  )
}
