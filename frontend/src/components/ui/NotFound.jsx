import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import Logo from '../Logo'

/**
 * Branded 404 page. Shown whenever the router lands on an unknown route OR a route's
 * Suspense + ErrorBoundary determines the chunk doesn't exist.
 */
export default function NotFound() {
  const { t } = useTranslation()
  const location = useLocation()

  return (
    <div
      className="min-h-[100dvh] flex flex-col items-center justify-center p-8 text-slate-100"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <div className="text-center max-w-md">
        <div className="mx-auto mb-6 opacity-90">
          <Logo size={56} />
        </div>
        <div className="text-7xl font-bold font-mono text-cyan-400/40 mb-2">404</div>
        <h1 className="text-xl font-semibold mb-3">
          {t('errors.unknown_route', { defaultValue: 'Page not found' })}
        </h1>
        <p className="text-sm text-white/55 mb-2 font-mono">
          <code className="text-cyan-300/80">{location.pathname}</code>
        </p>
        <p className="text-[13px] text-white/45 mb-8 leading-relaxed">
          The page you're looking for doesn't exist or was moved. If you reached this through
          a saved link, please update it.
        </p>
        <div className="flex gap-3 justify-center flex-wrap">
          <Link
            to="/"
            className="px-4 py-2 rounded-lg text-sm font-mono border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25"
          >
            ← Home
          </Link>
          <Link
            to="/status"
            className="px-4 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/30"
          >
            System status
          </Link>
        </div>
      </div>
    </div>
  )
}
