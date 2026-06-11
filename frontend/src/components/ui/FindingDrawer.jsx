import React, { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AnimatePresence, motion } from 'framer-motion'
import { ExternalLink, X } from 'lucide-react'
import SeverityBadge, { getSeverityMeta } from './SeverityBadge'
import KevEpssBadge from './KevEpssBadge'
import CopyButton from './CopyButton'

function Section({ title, children, className = '' }) {
  return (
    <section className={className}>
      <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-[0.18em] mb-2.5">
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
    <div className="flex items-start gap-3 py-1.5 border-b border-white/[0.04] last:border-0">
      <dt className="shrink-0 w-28 text-[10px] font-mono text-white/35 uppercase tracking-wide pt-0.5">
        {label}
      </dt>
      <dd className="flex-1 min-w-0 flex items-start gap-2">
        <span className="text-[12px] text-white/78 break-all font-mono ltr-only flex-1">
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
      <div className="relative rounded-xl border border-white/[0.08] bg-black/50 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-white/[0.06] bg-white/[0.02]">
          <span className="text-[9px] font-mono uppercase tracking-wider text-white/35">
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
  statusOptions,
  headerExtra,
  actions = [],
  subtitle,
}) {
  const { t } = useTranslation()
  const [statusUpdating, setStatusUpdating] = useState(false)

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

  const handleStatusChange = (e) => {
    const newStatus = e.target.value
    if (!newStatus || newStatus === finding?.status) return
    setStatusUpdating(true)
    onStatusUpdate?.(finding?.raw_id ?? finding?.id, newStatus)
    setTimeout(() => setStatusUpdating(false), 600)
  }

  const meta = getSeverityMeta(finding?.severity)
  const compliance = Array.isArray(finding?.compliance) ? finding.compliance : []

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
            className="fixed inset-0 z-[9000] bg-black/65 backdrop-blur-sm border-0 cursor-default"
            onClick={onClose}
            aria-label={t('components.findingDrawer.closeDrawer')}
          />

          <motion.aside
            key="drawer"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 32, stiffness: 300 }}
            className="fixed inset-y-0 right-0 z-[9001] w-full max-w-xl flex flex-col border-s border-white/10 bg-[#0a0f18]/97 backdrop-blur-xl shadow-2xl"
            role="dialog"
            aria-modal="true"
            aria-labelledby="finding-drawer-title"
          >
            {/* Header */}
            <div
              className="shrink-0 px-5 py-4 border-b border-white/10"
              style={{ borderBottomColor: `${meta.color}25` }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} size="md" showDot />
                    <KevEpssBadge kev={kev} epss={epss} compact />
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
                      <p className="text-[11px] font-mono text-white/45 truncate ltr-only flex-1">
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

                <button
                  type="button"
                  onClick={onClose}
                  className="shrink-0 p-1.5 rounded-lg text-white/40 hover:text-white/90 hover:bg-white/5 transition-colors"
                  aria-label={t('components.findingDrawer.close')}
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Action bar */}
              {(onStatusUpdate || actions.length > 0) && (
                <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-white/[0.06]">
                  {onStatusUpdate && (
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-white/35 uppercase tracking-wide">
                        {t('components.findingDrawer.status')}
                      </span>
                      <select
                        value={finding.status || 'OPEN'}
                        onChange={handleStatusChange}
                        disabled={statusUpdating}
                        className="bg-black/60 border border-white/15 rounded-lg px-2.5 py-1.5 text-[11px] font-mono text-white/75 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
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
                  {actions.map((action) => (
                    <button
                      key={action.label}
                      type="button"
                      onClick={action.onClick}
                      className={
                        action.variant === 'primary'
                          ? 'px-3 py-1.5 rounded-lg text-[11px] font-mono border border-cyan-500/35 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20'
                          : 'px-3 py-1.5 rounded-lg text-[11px] font-mono border border-white/10 text-white/55 hover:text-white/85 hover:border-white/25'
                      }
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6 custom-scroll text-sm">
              {finding.description && (
                <Section title={t('components.findingDrawer.description')}>
                  <p className="text-[13px] text-white/72 leading-relaxed whitespace-pre-wrap">
                    {finding.description}
                  </p>
                </Section>
              )}

              {finding.remediation && (
                <Section title={t('components.findingDrawer.remediation')}>
                  <p className="text-[13px] text-white/72 leading-relaxed whitespace-pre-wrap">
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
                            <span className="text-white/60 break-all">{u}</span>
                          )}
                        </li>
                      )
                    })}
                  </ul>
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
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}
