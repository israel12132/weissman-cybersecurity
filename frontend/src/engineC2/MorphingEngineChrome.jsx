/**
 * Morphing Engine C2 Chrome — polymorphic layout assembled from backend manifest capabilities.
 */
import React from 'react'
import { useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import AppShell from '../components/layout/AppShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import EngineIntegrationsBar from '../components/engine/EngineIntegrationsBar'
import EngineHubParamsBridge from '../components/engine/EngineHubParamsBridge'
import ForensicEngineRealityBadge from '../forensic/ForensicEngineRealityBadge'
import { useEngineHub } from '../context/EngineHubContext'
import { resolveRouteEvidence } from '../lib/routeEvidence'
import { useResolvedEngineManifest } from './EngineManifestContext'
import { EngineC2Boundary, EngineC2ControlProvider } from './EngineC2Boundary'
import KillSwitchBar from './modules/KillSwitchBar'
import TelemetryStrip from './modules/TelemetryStrip'

export default function MorphingEngineChrome({
  title,
  subtitle,
  badge,
  badgeColor,
  icon,
  actions,
  breadcrumbs,
  children,
  contentClassName,
  maxWidth,
  engineId: engineIdProp,
  evidence,
  hideEvidence = false,
  syncAt,
  hideHubParams = false,
  /** Override manifest (tests) */
  manifest: manifestOverride,
}) {
  const { pathname } = useLocation()
  const { t } = useTranslation()
  const { hubClientId } = useEngineHub()
  const resolvedManifest = useResolvedEngineManifest({ pathname, engineId: engineIdProp })
  const manifest = manifestOverride ?? resolvedManifest
  const engineId = engineIdProp ?? manifest?.engine_id ?? null
  const caps = manifest?.capabilities ?? {}
  const chromeColor = badgeColor ?? manifest?.chrome?.badge_color ?? '#22d3ee'

  let evidenceNode = null
  if (evidence === false || hideEvidence) {
    evidenceNode = null
  } else if (evidence != null) {
    evidenceNode = typeof evidence === 'string'
      ? <EvidenceNotice className="mb-6">{evidence}</EvidenceNotice>
      : evidence
  } else if (manifest?.evidence_i18n_key) {
    const text = t(manifest.evidence_i18n_key)
    if (text && text !== manifest.evidence_i18n_key) {
      evidenceNode = <EvidenceNotice className="mb-6">{text}</EvidenceNotice>
    }
  } else {
    const auto = resolveRouteEvidence(pathname, t)
    if (auto) {
      evidenceNode = <EvidenceNotice className="mb-6">{auto}</EvidenceNotice>
    }
  }

  const inner = (
    <>
      {evidenceNode}
      {engineId && (
        <div className="flex flex-wrap items-center gap-2 mb-5">
          <ForensicEngineRealityBadge engineId={engineId} size="sm" showRemote showCanonical />
        </div>
      )}
      <KillSwitchBar />
      <TelemetryStrip
        engineId={engineId}
        live={!!caps.needs_live_telemetry}
        memory={!!caps.needs_memory_telemetry}
      />
      {engineId && caps.requires_scan_dispatch !== false && (
        <EngineIntegrationsBar
          engineId={engineId}
          clientId={hubClientId}
          className="mb-5"
        />
      )}
      {engineId && caps.requires_scan_dispatch !== false && !hideHubParams && (
        <EngineHubParamsBridge
          engineId={engineId}
          clientId={hubClientId}
          className="mb-5"
        />
      )}
      {syncAt && (
        <p className="text-[10px] font-mono text-white/35 -mt-3 mb-5">
          {t('weissmanFindings.last_updated', { time: new Date(syncAt).toLocaleString() })}
        </p>
      )}
      {engineId && caps.requires_agent_gate ? (
        <AgentRequiredGate engineId={engineId}>{children}</AgentRequiredGate>
      ) : (
        children
      )}
    </>
  )

  return (
    <EngineC2ControlProvider killSwitchEnabled={!!caps.requires_kill_switch}>
      <AppShell
        title={title}
        subtitle={subtitle}
        badge={badge}
        badgeColor={chromeColor}
        icon={icon}
        actions={actions}
        breadcrumbs={breadcrumbs}
        contentClassName={contentClassName}
        maxWidth={maxWidth}
      >
        <EngineC2Boundary>{inner}</EngineC2Boundary>
      </AppShell>
    </EngineC2ControlProvider>
  )
}
