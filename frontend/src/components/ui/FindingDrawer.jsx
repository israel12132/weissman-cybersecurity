import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import useFocusTrap from '../../hooks/useFocusTrap'
import { AnimatePresence, motion } from 'framer-motion'
import { ExternalLink, X } from 'lucide-react'
import SeverityBadge, { getSeverityMeta } from './SeverityBadge'
import KevEpssBadge from './KevEpssBadge'
import CopyButton from './CopyButton'
import SupplyChainGraph from './SupplyChainGraph'
import FindingVerifyButton, { LiveVerdictBadge } from '../findings/FindingLiveVerify'
import Button from './Button'

const REACH_META = {
  client_runtime: { color: '#fb7185', key: 'client_runtime' },
  direct: { color: '#fbbf24', key: 'direct' },
  transitive: { color: '#38bdf8', key: 'transitive' },
  declared: { color: '#94a3b8', key: 'declared' },
}

function ReachabilityBadge({ tier, t }) {
  if (!tier) return null
  const m = REACH_META[tier] ?? REACH_META.declared
  return (
    <span
      className="text-[10px] font-mono px-2 py-0.5 rounded border"
      style={{ color: m.color, borderColor: `${m.color}55`, background: `${m.color}12` }}
    >
      {t(`components.findingDrawer.supplyChain.${m.key}`)}
    </span>
  )
}

function DependencyPathChain({ path }) {
  if (!Array.isArray(path) || path.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {path.map((node, i) => {
        const isLast = i === path.length - 1
        const isFirst = i === 0
        const cls = isLast
          ? 'border-rose-500/40 text-rose-200 bg-rose-500/10'
          : isFirst
            ? 'border-amber-500/40 text-amber-200 bg-amber-500/10'
            : 'border-[var(--border-strong)] text-[var(--text-secondary)]'
        return (
          <React.Fragment key={`${node}-${i}`}>
            <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ltr-only ${cls}`}>
              {node}
            </span>
            {!isLast && <span className="text-[var(--text-disabled)] text-xs">→</span>}
          </React.Fragment>
        )
      })}
    </div>
  )
}

function Section({ title, children, className = '' }) {
  return (
    <section className={className}>
      <h3 className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-[0.18em] mb-2.5">
        {title}
      </h3>
      {children}
    </section>
  )
}

function MetaRow({ label, value, copyable = false }) {
  if (value == null || value === '') return null
  const text = String(value)
  return (
    <div className="flex items-start gap-3 py-1.5 border-b border-[var(--border-subtle)] last:border-0">
      <dt className="shrink-0 w-28 text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide pt-0.5">
        {label}
      </dt>
      <dd className="flex-1 min-w-0 flex items-start gap-2">
        <span className="text-[12px] text-[var(--text-secondary)] break-all font-mono ltr-only flex-1">
          {text}
        </span>
        {copyable && <CopyButton value={text} size="sm" />}
      </dd>
    </div>
  )
}

function EvidenceBlock({ title, content, copyable = true, evidenceLabel, copyLabel }) {
  if (!content) return null
  const text = typeof content === 'string' ? content : JSON.stringify(content, null, 2)
  return (
    <Section title={title}>
      <div className="relative rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] overflow-hidden">
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-[var(--border-subtle)] bg-[var(--row-hover-bg)]">
          <span className="text-[9px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
            {evidenceLabel}
          </span>
          {copyable && <CopyButton value={text} size="md" label={copyLabel} />}
        </div>
        <pre className="p-3 text-[11px] font-mono text-emerald-300/85 overflow-x-auto max-h-72 whitespace-pre-wrap break-all leading-relaxed m-0 custom-scroll">
          {text}
        </pre>
      </div>
    </Section>
  )
}

/**
 * Right-side finding detail drawer with framer-motion slide-in.
 */
export default function FindingDrawer({
  finding,
  onClose,
  onStatusUpdate,
  onVerifyComplete,
  statusOptions,
  headerExtra,
  actions = [],
  subtitle,
}) {
  const { t } = useTranslation()
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [activeTab, setActiveTab] = useState('evidence')
  const dialogRef = useRef(null)
  const tabRefs = useRef([])
  useFocusTrap(dialogRef, Boolean(finding))

  const drawerTabs = useMemo(
    () => [
      { id: 'evidence', label: 'Evidence' },
      { id: 'mitre', label: 'MITRE' },
      { id: 'remediation', label: 'Remediation' },
      { id: 'playbook', label: 'Playbook' },
      { id: 'compliance', label: 'Compliance' },
      { id: 'financial', label: 'Financial' },
    ],
    [],
  )

  const onTabKeyDown = (e, index) => {
    const last = drawerTabs.length - 1
    let next = null
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = index === last ? 0 : index + 1
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = index === 0 ? last : index - 1
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = last
    if (next === null) return
    e.preventDefault()
    setActiveTab(drawerTabs[next].id)
    tabRefs.current[next]?.focus()
  }

  const defaultStatusOptions = useMemo(
    () => [
      { value: 'OPEN', label: t('components.findingDrawer.statusOpen') },
      { value: 'ACKNOWLEDGED', label: t('components.findingDrawer.statusAcknowledged') },
      { value: 'IN_PROGRESS', label: t('components.findingDrawer.statusInProgress') },
      { value: 'FIXED', label: t('components.findingDrawer.statusFixed') },
      { value: 'FALSE_POSITIVE', label: t('components.findingDrawer.statusFalsePositive') },
    ],
    [t],
  )

  const resolvedStatusOptions = statusOptions ?? defaultStatusOptions

  useEffect(() => {
    if (!finding) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [finding, onClose])

  const references = useMemo(() => {
    const refs = finding?.references ?? finding?.refs ?? finding?.reference_urls ?? null
    if (!refs) return []
    if (Array.isArray(refs)) return refs.filter(Boolean).map(String)
    if (typeof refs === 'string') {
      const s = refs.trim()
      if (!s) return []
      try {
        const parsed = JSON.parse(s)
        if (Array.isArray(parsed)) return parsed.filter(Boolean).map(String)
      } catch {
        // comma/newline separated
      }
      return s
        .split(/[\n,]+/g)
        .map((x) => x.trim())
        .filter(Boolean)
    }
    return [String(refs)]
  }, [finding])

  const pocText =
    finding?.proof_of_concept ||
    finding?.proof ||
    finding?.poc ||
    finding?.poc_text ||
    finding?.poc_exploit ||
    null

  const cve = finding?.cve || finding?.cve_id
  const kev = finding?.kev ?? finding?.is_kev ?? finding?.cisa_kev
  const epss = finding?.epss ?? finding?.epss_score
  const seenCount = finding?.seen_count ?? 1
  const clusterId = finding?.cluster_id
  const priorityScore = finding?.priority_score ?? finding?.risk_score

  const handleStatusChange = (e) => {
    const newStatus = e.target.value
    if (!newStatus || newStatus === finding?.status) return
    setStatusUpdating(true)
    onStatusUpdate?.(finding?.raw_id ?? finding?.id, newStatus)
    setTimeout(() => setStatusUpdating(false), 600)
  }

  const meta = getSeverityMeta(finding?.severity)
  const compliance = Array.isArray(finding?.compliance) ? finding.compliance : []

  // Supply-chain fields live at top level (job result) or under `raw` (findings API).
  const scGet = (k) => finding?.[k] ?? finding?.raw?.[k]
  const scPackage = scGet('package')
  const scReach = scGet('reachability')
  const scPath = scGet('dependency_path')
  const scComponents = scGet('components')
  const scEdges = scGet('dependency_edges')
  const scOsvIds = scGet('osv_ids')
  const scOsvSummaries = scGet('osv_summaries')
  const scVectors = scGet('cvss_vectors')
  const isSupplyChain =
    scGet('type') === 'supply_chain' ||
    Boolean(scPackage) ||
    Boolean(scReach) ||
    (Array.isArray(scComponents) && scComponents.length > 0) ||
    (Array.isArray(scPath) && scPath.length > 0)

  return (
    <AnimatePresence>
      {finding && (
        <>
          <motion.button
            key="backdrop"
            type="button"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[9000] bg-[var(--bg-3)] backdrop-blur-sm border-0 cursor-default"
            onClick={onClose}
            aria-label={t('components.findingDrawer.closeDrawer')}
          />

          <motion.aside
            key="drawer"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 32, stiffness: 300 }}
            className="fixed inset-y-0 right-0 z-[9001] w-full max-w-xl flex flex-col border-s border-[var(--border-default)] bg-[var(--bg-elevated)] backdrop-blur-xl shadow-2xl"
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="finding-drawer-title"
          >
            {/* Header */}
            <div
              className="shrink-0 px-5 py-4 border-b border-[var(--border-default)]"
              style={{ borderBottomColor: `${meta.color}25` }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} size="md" showDot />
                    <KevEpssBadge kev={kev} epss={epss} compact />
                    {priorityScore != null && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)]">
                        Priority {Number(priorityScore).toFixed(1)}
                      </span>
                    )}
                    {seenCount > 1 && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30 text-amber-300/90">
                        Seen {seenCount}×
                      </span>
                    )}
                    {clusterId != null && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/20 text-cyan-300/70">
                        Cluster #{clusterId}
                      </span>
                    )}
                    <LiveVerdictBadge
                      verification={finding.live_verification || finding.raw?.live_verification}
                      verdict={finding.live_verdict}
                    />
                    {finding.attestation_valid && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-300/90">
                        {t('components.findingDrawer.attestationValid')}
                      </span>
                    )}
                    {headerExtra}
                  </div>

                  <h2
                    id="finding-drawer-title"
                    className="text-base font-semibold text-[var(--accent-strong)] leading-snug"
                  >
                    {finding.title || finding.type || t('components.findingDrawer.defaultTitle')}
                  </h2>

                  {(subtitle || finding.target) && (
                    <div className="flex items-center gap-2 min-w-0">
                      <p className="text-[11px] font-mono text-[var(--text-muted)] truncate ltr-only flex-1">
                        {subtitle ?? finding.target}
                      </p>
                      {(finding.target || cve) && (
                        <CopyButton value={finding.target || cve} size="sm" />
                      )}
                    </div>
                  )}

                  {cve && (
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-300/90 hover:text-cyan-200 transition-colors ltr-only"
                      >
                        {cve}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                      <CopyButton value={cve} size="sm" label={t('components.findingDrawer.copyCve')} />
                    </div>
                  )}

                  {finding.mitre_attack && (
                    <a
                      href={`https://attack.mitre.org/techniques/${String(finding.mitre_attack).replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] font-mono text-cyan-300/75 hover:underline"
                    >
                      MITRE {finding.mitre_attack}
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  )}
                </div>

                <Button variant="unstyled"
                  type="button"
                  onClick={onClose}
                  className="shrink-0 p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] transition-colors"
                  aria-label={t('components.findingDrawer.close')}
                >
                  <X className="w-5 h-5" />
                </Button>
              </div>

              {/* Action bar */}
              <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-[var(--border-subtle)]">
                  {onStatusUpdate && (
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">
                        {t('components.findingDrawer.status')}
                      </span>
                      <select
                        value={finding.status || 'OPEN'}
                        onChange={handleStatusChange}
                        disabled={statusUpdating}
                        aria-label={t('components.findingDrawer.status')}
                        className="bg-[var(--scrim)] border border-[var(--border-strong)] rounded-lg px-2.5 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
                      >
                        {resolvedStatusOptions.map((s) => (
                          <option key={s.value} value={s.value}>
                            {s.label}
                          </option>
                        ))}
                      </select>
                      {statusUpdating && (
                        <div className="w-3.5 h-3.5 border-2 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin" />
                      )}
                    </div>
                  )}
                  <FindingVerifyButton
                    finding={finding}
                    onVerified={(rawId, verification) => onVerifyComplete?.(rawId, verification)}
                    variant="primary"
                  />
                  {actions.map((action) => (
                    <Button variant="unstyled"
                      key={action.label}
                      type="button"
                      onClick={action.onClick}
                      className={
                        action.variant === 'primary'
                          ? 'px-3 py-1.5 rounded-lg text-[11px] font-mono border border-cyan-500/35 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20'
                          : 'px-3 py-1.5 rounded-lg text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)]'
                      }
                    >
                      {action.label}
                    </Button>
                  ))}
                </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6 custom-scroll text-sm">
              <div
                role="tablist"
                aria-label={t('components.findingDrawer.detailTabs')}
                className="flex flex-wrap gap-1 border-b border-[var(--border-subtle)] pb-3 -mt-1"
              >
                {drawerTabs.map((tab, index) => (
                  <Button variant="unstyled"
                    key={tab.id}
                    ref={(el) => { tabRefs.current[index] = el }}
                    type="button"
                    role="tab"
                    id={`finding-tab-${tab.id}`}
                    aria-selected={activeTab === tab.id}
                    aria-controls="finding-tabpanel"
                    tabIndex={activeTab === tab.id ? 0 : -1}
                    onClick={() => setActiveTab(tab.id)}
                    onKeyDown={(e) => onTabKeyDown(e, index)}
                    className={`text-[10px] font-mono uppercase tracking-wider px-2.5 py-1 rounded-md border transition-colors ${
                      activeTab === tab.id
                        ? 'border-cyan-500/40 text-cyan-200 bg-cyan-500/10'
                        : 'border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
                    }`}
                  >
                    {tab.label}
                  </Button>
                ))}
              </div>

              <div
                role="tabpanel"
                id="finding-tabpanel"
                aria-labelledby={`finding-tab-${activeTab}`}
                tabIndex={0}
                className="space-y-6 focus:outline-none"
              >

              {activeTab === 'evidence' && (
              <>
              {finding.description && (
                <Section title={t('components.findingDrawer.description')}>
                  <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                    {finding.description}
                  </p>
                </Section>
              )}

              {finding.remediation && (
                <Section title={t('components.findingDrawer.remediation')}>
                  <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                    {finding.remediation}
                  </p>
                </Section>
              )}

              <Section title={t('components.findingDrawer.technicalDetails')}>
                <dl>
                  <MetaRow label={t('components.findingDrawer.target')} value={finding.target} copyable />
                  <MetaRow
                    label={t('components.findingDrawer.affectedUrl')}
                    value={finding.url ?? finding.affected_url ?? finding.target_url}
                    copyable
                  />
                  <MetaRow label={t('components.findingDrawer.riskScore')} value={finding.risk_score} />
                  <MetaRow label={t('components.findingDrawer.cvss')} value={finding.cvss_score ?? finding.score} />
                  <MetaRow label={t('components.findingDrawer.cwe')} value={finding.cwe_id ?? finding.cwe ?? finding.cweId} />
                  <MetaRow label={t('components.findingDrawer.source')} value={finding.source ?? finding.engine} />
                  <MetaRow label={t('components.findingDrawer.status')} value={finding.status} />
                  <MetaRow
                    label={t('components.findingDrawer.discovered')}
                    value={
                      finding.discovered_at || finding.created_at
                        ? new Date(finding.discovered_at || finding.created_at).toLocaleString()
                        : null
                    }
                  />
                  <MetaRow label={t('components.findingDrawer.findingId')} value={finding.finding_id} copyable />
                  <MetaRow label={t('components.findingDrawer.clientId')} value={finding.client_id} copyable />
                  <MetaRow label={t('components.findingDrawer.runId')} value={finding.run_id} copyable />
                  <MetaRow
                    label={t('components.findingDrawer.pocSha256')}
                    value={finding.poc_commitment_sha256}
                    copyable
                  />
                </dl>
              </Section>

              {compliance.length > 0 && (
                <Section title={t('components.findingDrawer.complianceImpact')}>
                  <div className="flex flex-wrap gap-1.5">
                    {compliance.map((tag, i) => (
                      <span
                        key={i}
                        className="text-[10px] font-mono px-2 py-0.5 rounded border border-violet-500/25 text-violet-200/80 bg-violet-500/5"
                      >
                        {typeof tag === 'string' ? tag : JSON.stringify(tag)}
                      </span>
                    ))}
                  </div>
                </Section>
              )}

              {pocText && (
                <EvidenceBlock
                  title={t('components.findingDrawer.proofPoc')}
                  content={String(pocText)}
                  copyable
                  evidenceLabel={t('components.findingDrawer.evidence')}
                  copyLabel={t('components.findingDrawer.copy')}
                />
              )}

              {references.length > 0 && (
                <Section title={t('components.findingDrawer.references')}>
                  <ul className="space-y-1.5">
                    {references.slice(0, 50).map((u, idx) => {
                      const isHttp = /^https?:\/\//i.test(u)
                      return (
                        <li key={`${u}-${idx}`} className="text-[12px] font-mono">
                          {isHttp ? (
                            <a
                              href={u}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-300/80 hover:text-cyan-200 underline break-all inline-flex items-center gap-1"
                            >
                              {u}
                              <ExternalLink className="w-3 h-3 shrink-0" />
                            </a>
                          ) : (
                            <span className="text-[var(--text-tertiary)] break-all">{u}</span>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                </Section>
              )}

              {isSupplyChain && (
                <Section title={t('components.findingDrawer.supplyChain.title')}>
                  <div className="space-y-4">
                    {(scReach || scGet('is_direct_dependency') === true) && (
                      <div className="flex flex-wrap items-center gap-2">
                        <ReachabilityBadge tier={scReach} t={t} />
                        {scGet('is_direct_dependency') === true && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30 text-amber-300/90">
                            {t('components.findingDrawer.supplyChain.directDependency')}
                          </span>
                        )}
                      </div>
                    )}

                    {(scPackage || scGet('ecosystem') || scGet('version') || scGet('evidence_kind')) && (
                      <dl>
                        <MetaRow
                          label={t('components.findingDrawer.supplyChain.package')}
                          value={scPackage}
                          copyable
                        />
                        <MetaRow
                          label={t('components.findingDrawer.supplyChain.ecosystem')}
                          value={scGet('ecosystem')}
                        />
                        <MetaRow
                          label={t('components.findingDrawer.supplyChain.version')}
                          value={scGet('version')}
                          copyable
                        />
                        <MetaRow
                          label={t('components.findingDrawer.supplyChain.evidenceSource')}
                          value={scGet('evidence_kind')}
                        />
                        <MetaRow
                          label={t('components.findingDrawer.affectedUrl')}
                          value={scGet('evidence_url')}
                          copyable
                        />
                      </dl>
                    )}

                    {Array.isArray(scPath) && scPath.length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">
                          {t('components.findingDrawer.supplyChain.dependencyPath')}
                        </p>
                        <DependencyPathChain path={scPath} />
                      </div>
                    )}

                    {Array.isArray(scOsvIds) && scOsvIds.length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">
                          {t('components.findingDrawer.supplyChain.advisories')}
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {scOsvIds.slice(0, 40).map((id) => {
                            const isCve = /^CVE-/i.test(String(id))
                            const href = isCve
                              ? `https://nvd.nist.gov/vuln/detail/${id}`
                              : `https://osv.dev/vulnerability/${id}`
                            return (
                              <a
                                key={String(id)}
                                href={href}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/25 text-cyan-200/85 hover:bg-cyan-500/10 ltr-only"
                              >
                                {String(id)}
                              </a>
                            )
                          })}
                        </div>
                      </div>
                    )}

                    {Array.isArray(scOsvSummaries) && scOsvSummaries.length > 0 && (
                      <ul className="space-y-1">
                        {scOsvSummaries.slice(0, 12).map((s, i) => (
                          <li key={i} className="text-[12px] text-[var(--text-tertiary)] leading-snug">
                            • {String(s)}
                          </li>
                        ))}
                      </ul>
                    )}

                    {Array.isArray(scVectors) && scVectors.length > 0 && (
                      <dl>
                        {scVectors.slice(0, 6).map((v, i) => (
                          <MetaRow
                            key={i}
                            label={t('components.findingDrawer.supplyChain.cvssVector')}
                            value={String(v)}
                            copyable
                          />
                        ))}
                      </dl>
                    )}

                    {(Array.isArray(scComponents) || Array.isArray(scEdges)) && (
                      <div className="space-y-2">
                        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">
                          {t('components.findingDrawer.supplyChain.dependencyGraph')}
                        </p>
                        <SupplyChainGraph
                          components={Array.isArray(scComponents) ? scComponents : []}
                          edges={Array.isArray(scEdges) ? scEdges : []}
                          direct={scGet('direct_dependencies') || []}
                          summary={scGet('dependency_graph') || null}
                          byReach={scGet('by_reachability') || null}
                          t={t}
                        />
                      </div>
                    )}
                  </div>
                </Section>
              )}

              {finding.raw != null && (
                <EvidenceBlock
                  title={t('components.findingDrawer.rawEvidence')}
                  content={finding.raw}
                  copyable
                  evidenceLabel={t('components.findingDrawer.evidence')}
                  copyLabel={t('components.findingDrawer.copy')}
                />
              )}
              </>
              )}

              {activeTab === 'mitre' && (
                <Section title="MITRE ATT&CK">
                  <MetaRow label="Technique" value={finding.mitre_attack ?? finding.raw?.mitre_attack} copyable />
                  <MetaRow label="CWE" value={finding.cwe_id ?? finding.cwe} copyable />
                  {finding.mitre_attack && (
                    <a
                      href={`https://attack.mitre.org/techniques/${String(finding.mitre_attack).replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] text-cyan-300/80 hover:underline inline-flex items-center gap-1 mt-2"
                    >
                      Open MITRE technique <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </Section>
              )}

              {activeTab === 'remediation' && (
                <Section title={t('components.findingDrawer.remediation')}>
                  <p className="text-[13px] text-[var(--text-secondary)] whitespace-pre-wrap">
                    {finding.remediation || finding.raw?.remediation || t('components.findingDrawer.noRemediation')}
                  </p>
                </Section>
              )}

              {activeTab === 'playbook' && (
                <Section title="SOAR / Playbook">
                  <MetaRow label="Engine" value={finding.source ?? finding.engine} />
                  <MetaRow label="Playbook hint" value={finding.raw?.playbook_id ?? finding.playbook_id} />
                  <p className="text-[11px] text-[var(--text-muted)] mt-2">
                    Fire from Playbooks hub or POST /api/playbooks/fire with this finding id.
                  </p>
                </Section>
              )}

              {activeTab === 'compliance' && (
                <Section title={t('components.findingDrawer.complianceImpact')}>
                  {compliance.length === 0 ? (
                    <p className="text-[var(--text-muted)] text-[12px]">No compliance tags on this finding.</p>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {compliance.map((tag, i) => (
                        <span
                          key={i}
                          className="text-[10px] font-mono px-2 py-0.5 rounded border border-violet-500/25 text-violet-200/80 bg-violet-500/5"
                        >
                          {typeof tag === 'string' ? tag : JSON.stringify(tag)}
                        </span>
                      ))}
                    </div>
                  )}
                </Section>
              )}

              {activeTab === 'financial' && (
                <Section title="Financial impact">
                  <MetaRow label="Priority score" value={priorityScore} />
                  <MetaRow label="CVSS" value={finding.cvss_score ?? finding.score} />
                  <MetaRow label="EPSS" value={epss} />
                  <MetaRow
                    label="Blast radius"
                    value={finding.raw?.financial_blast_radius ?? finding.financial_blast_radius}
                  />
                </Section>
              )}
              </div>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}
