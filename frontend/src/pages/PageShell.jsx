/**
 * Shared page shell for domain-specific intelligence hubs.
 * Wraps a page in consistent header/layout with navigation back to the matrix.
 */
import React from 'react'
import { Link } from 'react-router-dom'

export default function PageShell({ title, subtitle, badge, badgeColor = '#22d3ee', children }) {
  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex flex-wrap items-center gap-3">
          <Link to="/" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
            ← Dashboard
          </Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
            Engine Matrix
          </Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/findings" className="text-amber-400/60 hover:text-amber-300 text-xs font-mono transition-colors">
            Findings C2
          </Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/council-queue" className="text-amber-400/60 hover:text-amber-300 text-xs font-mono transition-colors">
            Council Queue
          </Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/sso-config" className="text-purple-400/60 hover:text-purple-300 text-xs font-mono transition-colors">
            SSO Config
          </Link>
          <span className="text-white/20 text-xs">|</span>
          {badge && (
            <span
              className="text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-widest border"
              style={{ color: badgeColor, borderColor: `${badgeColor}40`, backgroundColor: `${badgeColor}10` }}
            >
              {badge}
            </span>
          )}
          <h1 className="text-sm font-bold text-white">{title}</h1>
          {subtitle && (
            <span className="text-[10px] font-mono text-white/30">{subtitle}</span>
          )}
        </div>
      </header>
      <main className="max-w-screen-2xl mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  )
}
