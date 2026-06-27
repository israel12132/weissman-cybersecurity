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
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import EngineIntegrationsBar from '../components/engine/EngineIntegrationsBar'
import EngineHubParamsBridge from '../components/engine/EngineHubParamsBridge'
import EngineRealityBadge from '../components/EngineRealityBadge'
import { useEngineHub } from '../context/EngineHubContext'
import { resolveRouteEvidence } from '../lib/routeEvidence'
import { resolveRouteEngineId } from '../lib/routeEngineId'

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
  /** When set, agent-required engines show empty state until an endpoint agent is online */
  engineId,
  /** Custom evidence node/string; pass false to suppress auto banner */
  evidence,
  hideEvidence = false,
  /** ISO timestamp shown below evidence banner */
  syncAt,
  /** Profile pages with full EngineScanParamsPanel — skip compact hub bridge */
  hideHubParams = false,
}) {
  const { pathname } = useLocation()
  const { t } = useTranslation()
  const { hubClientId } = useEngineHub()
  const resolvedEngineId = engineId ?? resolveRouteEngineId(pathname)

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
      {resolvedEngineId && (
        <div className="flex flex-wrap items-center gap-2 mb-5">
          <EngineRealityBadge engineId={resolvedEngineId} size="sm" showRemote />
        </div>
      )}
      {resolvedEngineId && (
        <EngineIntegrationsBar
          engineId={resolvedEngineId}
          clientId={hubClientId}
          className="mb-5"
        />
      )}
      {resolvedEngineId && !hideHubParams && (
        <EngineHubParamsBridge
          engineId={resolvedEngineId}
          clientId={hubClientId}
          className="mb-5"
        />
      )}
      {syncAt && (
        <p className="text-[10px] font-mono text-white/35 -mt-3 mb-5">
          {t('weissmanFindings.last_updated', { time: new Date(syncAt).toLocaleString() })}
        </p>
      )}
      {resolvedEngineId ? (
        <AgentRequiredGate engineId={resolvedEngineId}>{children}</AgentRequiredGate>
      ) : (
        children
      )}
    </AppShell>
  )
}
