import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ChevronRight, Search } from 'lucide-react'
import AppSidebar from './AppSidebar'
import ProfileMenu from '../ui/ProfileMenu'
import { openCommandPalette } from '../GlobalSearch'
import RateLimitStatus from '../RateLimitStatus'
import NotificationBell from './NotificationBell'
import ScanStatusIndicator from './ScanStatusIndicator'
import { buildBreadcrumbs } from '../../lib/appNav'
import Button from '../ui/Button'

// Themeable via the --shell-bg token (flips with data-theme).
const SHELL_BG = 'var(--shell-bg)'

function BreadcrumbTrail({ crumbs }) {
  if (!crumbs.length) return null
  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 min-w-0 text-[11px] font-mono">
      {crumbs.map((crumb, i) => {
        const isLast = i === crumbs.length - 1
        return (
          <React.Fragment key={`${crumb.label}-${i}`}>
            {i > 0 && <ChevronRight className="w-3 h-3 text-[var(--text-muted)] shrink-0" aria-hidden />}
            {crumb.to && !isLast ? (
              <Link
                to={crumb.to}
                className="text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] transition-colors truncate max-w-[10rem]"
              >
                {crumb.label}
              </Link>
            ) : (
              <span
                className={[
                  'truncate max-w-[14rem]',
                  isLast ? 'text-[var(--text-secondary)]' : 'text-[var(--text-muted)]',
                ].join(' ')}
                aria-current={isLast ? 'page' : undefined}
              >
                {crumb.label}
              </span>
            )}
          </React.Fragment>
        )
      })}
    </nav>
  )
}

/**
 * Unified application shell for all non-cockpit hub pages.
 * Slim sticky header + left nav groups + consistent content rhythm.
 */
export default function AppShell({
  title,
  subtitle,
  badge,
  badgeColor = '#22d3ee',
  icon,
  actions,
  breadcrumbs: breadcrumbsOverride,
  children,
  contentClassName = '',
  maxWidth = 'max-w-screen-2xl',
}) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const modKey =
    typeof navigator !== 'undefined' &&
    /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent || '')
      ? '⌘'
      : 'Ctrl+'

  const breadcrumbs =
    breadcrumbsOverride ??
    buildBreadcrumbs(pathname, { pageTitle: title, t })

  return (
    <div
      className="min-h-[100dvh] text-[var(--text-secondary)] flex"
      style={{ background: SHELL_BG }}
    >
      <AppSidebar />

      <div className="flex-1 flex flex-col min-w-0 lg:pl-0">
        <header className="print:hidden sticky top-0 z-30 border-b border-[var(--border-default)] bg-[var(--header-surface)] backdrop-blur-xl">
          <div className={`${maxWidth} mx-auto px-4 pt-14 lg:pt-0`}>
            <div className="flex items-center justify-end gap-2 py-2 border-b border-[var(--border-subtle)] min-h-[40px]">
              <div className="flex-1 min-w-0 mr-4">
                <BreadcrumbTrail crumbs={breadcrumbs} />
              </div>
              <Button variant="unstyled"
                type="button"
                onClick={openCommandPalette}
                aria-keyshortcuts="Meta+K Control+K"
                title={t('components.globalSearch.placeholder')}
                className="hidden sm:inline-flex items-center gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)] px-2.5 py-1.5 text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
              >
                <Search className="w-3.5 h-3.5" aria-hidden="true" />
                <span>{t('components.globalSearch.triggerLabel')}</span>
                <kbd className="px-1.5 py-0.5 rounded bg-white/10 text-[10px]">{modKey}K</kbd>
              </Button>
              <Button variant="unstyled"
                type="button"
                onClick={openCommandPalette}
                aria-label={t('components.globalSearch.placeholder')}
                className="sm:hidden inline-flex items-center justify-center rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)] p-1.5 text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              >
                <Search className="w-4 h-4" aria-hidden="true" />
              </Button>
              <ScanStatusIndicator />
              <RateLimitStatus compact />
              <NotificationBell />
              <ProfileMenu />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                {icon && (
                  <span className="shrink-0 text-[var(--text-secondary)] [&>svg]:w-5 [&>svg]:h-5">{icon}</span>
                )}
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    {badge && (
                      <span
                        className="text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-widest border shrink-0"
                        style={{
                          color: badgeColor,
                          borderColor: `${badgeColor}40`,
                          backgroundColor: `${badgeColor}10`,
                        }}
                      >
                        {badge}
                      </span>
                    )}
                    {title && (
                      <h1 className="text-base sm:text-lg font-semibold text-[var(--text-primary)] truncate">
                        {title}
                      </h1>
                    )}
                  </div>
                  {subtitle && (
                    <p className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5 truncate">
                      {subtitle}
                    </p>
                  )}
                </div>
              </div>

              {actions && (
                <div className="flex items-center gap-2 flex-wrap shrink-0">{actions}</div>
              )}
            </div>
          </div>
        </header>

        <main id="main-content" tabIndex={-1} className={`flex-1 outline-none ${maxWidth} mx-auto w-full px-4 py-6 sm:py-8 ${contentClassName}`}>
          {children}
        </main>
      </div>
    </div>
  )
}
