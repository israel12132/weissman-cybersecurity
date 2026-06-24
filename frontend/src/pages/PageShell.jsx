/**
 * Shared page shell for domain-specific intelligence hubs.
 * Thin wrapper around AppShell — backward compatible props.
 * Auto-injects live API evidence banner from routeEvidence unless suppressed.
 */
import React from 'react'
import { useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import AppShell from '../components/layout/AppShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { resolveRouteEvidence } from '../lib/routeEvidence'

export default function PageShell({
  title,
  subtitle,
  badge,
  badgeColor = '#22d3ee',
  icon,
  actions,
  breadcrumbs,
  children,
  contentClassName,
  maxWidth,
  /** Custom evidence node/string; pass false to suppress auto banner */
  evidence,
  hideEvidence = false,
  /** ISO timestamp shown below evidence banner */
  syncAt,
}) {
  const { pathname } = useLocation()
  const { t } = useTranslation()

  let evidenceNode = null
  if (evidence === false || hideEvidence) {
    evidenceNode = null
  } else if (evidence != null) {
    evidenceNode = typeof evidence === 'string'
      ? <EvidenceNotice className="mb-6">{evidence}</EvidenceNotice>
      : evidence
  } else {
    const auto = resolveRouteEvidence(pathname, t)
    if (auto) {
      evidenceNode = <EvidenceNotice className="mb-6">{auto}</EvidenceNotice>
    }
  }

  return (
    <AppShell
      title={title}
      subtitle={subtitle}
      badge={badge}
      badgeColor={badgeColor}
      icon={icon}
      actions={actions}
      breadcrumbs={breadcrumbs}
      contentClassName={contentClassName}
      maxWidth={maxWidth}
    >
      {evidenceNode}
      {syncAt && (
        <p className="text-[10px] font-mono text-white/35 -mt-3 mb-5">
          {t('weissmanFindings.last_updated', { time: new Date(syncAt).toLocaleString() })}
        </p>
      )}
      {children}
    </AppShell>
  )
}
