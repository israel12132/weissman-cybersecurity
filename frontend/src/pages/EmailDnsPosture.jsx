import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'
import { BoundClientScanField } from '../components/scan/ClientScanBinding'

// Command Center GUI for the `email_dns_posture` engine — Email & Domain Trust Posture.
// Every control maps 1:1 to a real engine parameter consumed from the scan body via job_params.
const ENGINE = 'email_dns_posture'
const ACCENT = '#34d399'

const TOGGLES = [
  { key: 'check_smtp_tls', labelKey: 'pages.emailDnsPosture.toggle_check_smtp_tls_label', hintKey: 'pages.emailDnsPosture.toggle_check_smtp_tls_hint', defaultVal: true },
  { key: 'check_mta_sts', labelKey: 'pages.emailDnsPosture.toggle_check_mta_sts_label', hintKey: 'pages.emailDnsPosture.toggle_check_mta_sts_hint', defaultVal: true },
  { key: 'check_dnssec', labelKey: 'pages.emailDnsPosture.toggle_check_dnssec_label', hintKey: 'pages.emailDnsPosture.toggle_check_dnssec_hint', defaultVal: true },
  { key: 'check_caa', labelKey: 'pages.emailDnsPosture.toggle_check_caa_label', hintKey: 'pages.emailDnsPosture.toggle_check_caa_hint', defaultVal: true },
  { key: 'check_bimi', labelKey: 'pages.emailDnsPosture.toggle_check_bimi_label', hintKey: 'pages.emailDnsPosture.toggle_check_bimi_hint', defaultVal: true },
  { key: 'check_dane', labelKey: 'pages.emailDnsPosture.toggle_check_dane_label', hintKey: 'pages.emailDnsPosture.toggle_check_dane_hint', defaultVal: false },
  { key: 'check_resolver_consensus', labelKey: 'pages.emailDnsPosture.toggle_check_resolver_consensus_label', hintKey: 'pages.emailDnsPosture.toggle_check_resolver_consensus_hint', defaultVal: true },
  { key: 'check_mail_subdomains', labelKey: 'pages.emailDnsPosture.toggle_check_mail_subdomains_label', hintKey: 'pages.emailDnsPosture.toggle_check_mail_subdomains_hint', defaultVal: true },
  { key: 'check_autodiscover', labelKey: 'pages.emailDnsPosture.toggle_check_autodiscover_label', hintKey: 'pages.emailDnsPosture.toggle_check_autodiscover_hint', defaultVal: true },
  { key: 'check_bimi_logo_fetch', labelKey: 'pages.emailDnsPosture.toggle_check_bimi_logo_fetch_label', hintKey: 'pages.emailDnsPosture.toggle_check_bimi_logo_fetch_hint', defaultVal: true },
  { key: 'check_dmarc_external_reports', labelKey: 'pages.emailDnsPosture.toggle_check_dmarc_external_reports_label', hintKey: 'pages.emailDnsPosture.toggle_check_dmarc_external_reports_hint', defaultVal: true },
  { key: 'check_mx_diversity', labelKey: 'pages.emailDnsPosture.toggle_check_mx_diversity_label', hintKey: 'pages.emailDnsPosture.toggle_check_mx_diversity_hint', defaultVal: true },
  { key: 'check_spf_ip_inventory', labelKey: 'pages.emailDnsPosture.toggle_check_spf_ip_inventory_label', hintKey: 'pages.emailDnsPosture.toggle_check_spf_ip_inventory_hint', defaultVal: true },
  { key: 'check_mx_tls_cert', labelKey: 'pages.emailDnsPosture.toggle_check_mx_tls_cert_label', hintKey: 'pages.emailDnsPosture.toggle_check_mx_tls_cert_hint', defaultVal: true },
  { key: 'check_mta_sts_mx_drift', labelKey: 'pages.emailDnsPosture.toggle_check_mta_sts_mx_drift_label', hintKey: 'pages.emailDnsPosture.toggle_check_mta_sts_mx_drift_hint', defaultVal: true },
  { key: 'check_ns_posture', labelKey: 'pages.emailDnsPosture.toggle_check_ns_posture_label', hintKey: 'pages.emailDnsPosture.toggle_check_ns_posture_hint', defaultVal: true },
  { key: 'check_soa_posture', labelKey: 'pages.emailDnsPosture.toggle_check_soa_posture_label', hintKey: 'pages.emailDnsPosture.toggle_check_soa_posture_hint', defaultVal: true },
  { key: 'check_bimi_vmc_fetch', labelKey: 'pages.emailDnsPosture.toggle_check_bimi_vmc_fetch_label', hintKey: 'pages.emailDnsPosture.toggle_check_bimi_vmc_fetch_hint', defaultVal: true },
  { key: 'subdomain_policy_required', labelKey: 'pages.emailDnsPosture.toggle_subdomain_policy_required_label', hintKey: 'pages.emailDnsPosture.toggle_subdomain_policy_required_hint', defaultVal: true },
  { key: 'strict_mode', labelKey: 'pages.emailDnsPosture.toggle_strict_mode_label', hintKey: 'pages.emailDnsPosture.toggle_strict_mode_hint', defaultVal: false },
]

const STANDARDS = [
  { key: 'spf', label: 'SPF' },
  { key: 'dkim', label: 'DKIM' },
  { key: 'dmarc', label: 'DMARC' },
  { key: 'mta_sts', label: 'MTA-STS' },
  { key: 'tls_rpt', label: 'TLS-RPT' },
  { key: 'smtp_tls', label: 'SMTP TLS' },
  { key: 'dnssec', label: 'DNSSEC' },
  { key: 'dane', label: 'DANE' },
  { key: 'caa', label: 'CAA' },
  { key: 'bimi', label: 'BIMI' },
]

const COMPLIANCE_KEYS = [
  { group: 'NIST SP 800-53', groupKey: 'pages.emailDnsPosture.compliance_group_nist', keys: [['SI-10', 'pages.emailDnsPosture.compliance_nist_si10'], ['SC-8', 'pages.emailDnsPosture.compliance_nist_sc8'], ['SC-20', 'pages.emailDnsPosture.compliance_nist_sc20'], ['AU-6', 'pages.emailDnsPosture.compliance_nist_au6']] },
  { group: 'CIS v8', groupKey: 'pages.emailDnsPosture.compliance_group_cis', keys: [['9_5', 'pages.emailDnsPosture.compliance_cis_95'], ['9_6', 'pages.emailDnsPosture.compliance_cis_96'], ['9_7', 'pages.emailDnsPosture.compliance_cis_97']] },
  { group: 'Regulatory', groupKey: 'pages.emailDnsPosture.compliance_group_regulatory', keys: [['gdpr_art_32', 'pages.emailDnsPosture.compliance_gdpr_art32'], ['nis2_email_security', 'pages.emailDnsPosture.compliance_nis2_email']] },
]

const TOXIC_STYLE = {
  critical: { bd: 'border-rose-500/40', bg: 'bg-rose-500/10', text: 'text-rose-300' },
  high: { bd: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-300' },
  medium: { bd: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-300' },
  low: { bd: 'border-sky-500/40', bg: 'bg-sky-500/10', text: 'text-sky-300' },
}

const SUBSCORES = [
  { key: 'spf', labelKey: 'pages.emailDnsPosture.subscore_spf' },
  { key: 'dmarc', labelKey: 'pages.emailDnsPosture.subscore_dmarc' },
  { key: 'dkim', labelKey: 'pages.emailDnsPosture.subscore_dkim' },
  { key: 'transport', labelKey: 'pages.emailDnsPosture.subscore_transport' },
  { key: 'dns_trust', labelKey: 'pages.emailDnsPosture.subscore_dns_trust' },
]

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

const SPOOF_STYLE = {
  protected: { color: '#34d399', bg: 'bg-emerald-500/10', bd: 'border-emerald-500/30', icon: '🛡', labelKey: 'pages.emailDnsPosture.spoof_protected' },
  partial: { color: '#fbbf24', bg: 'bg-amber-500/10', bd: 'border-amber-500/30', icon: '⚠', labelKey: 'pages.emailDnsPosture.spoof_partial' },
  spoofable: { color: '#fb7185', bg: 'bg-rose-500/10', bd: 'border-rose-500/30', icon: '☠', labelKey: 'pages.emailDnsPosture.spoof_spoofable' },
}

function gradeColor(grade) {
  return {
    'A+': '#34d399', A: '#34d399', 'A-': '#34d399',
    B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#fb7185',
  }[grade] || '#fb7185'
}
function sevValue(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0
}
function isSummary(f) {
  return f && (f.category === 'summary' || typeof f.grade === 'string')
}

// Derive a per-standard status from the summary's `details` block.
function standardStatus(details, key, t) {
  if (!details) return { state: 'unknown', detail: '' }
  const d = details
  switch (key) {
    case 'spf': {
      const s = d.spf || {}
      if (!s.present) return { state: 'fail', detail: t('pages.emailDnsPosture.status_no_record') }
      const q = s.qualifier
      const good = (q === '-' || q === '~') && !s.over_limit
      return { state: good ? 'pass' : 'warn', detail: `${q ? `${q}all` : t('pages.emailDnsPosture.status_neutral')}${s.over_limit ? ` · ${t('pages.emailDnsPosture.status_over_limit')}` : ''}` }
    }
    case 'dkim': {
      const s = d.dkim || {}
      const n = Array.isArray(s.selectors_found) ? s.selectors_found.length : 0
      if (n === 0 && !s.ed25519) return { state: 'warn', detail: t('pages.emailDnsPosture.status_none_found') }
      const selWord = n === 1 ? t('pages.emailDnsPosture.status_selector_one') : t('pages.emailDnsPosture.status_selector_other')
      return { state: 'pass', detail: `${n} ${selWord}${s.min_key_bits ? ` · ${t('pages.emailDnsPosture.cert_bits', { bits: s.min_key_bits })}` : ''}` }
    }
    case 'dmarc': {
      const s = d.dmarc || {}
      if (!s.present) return { state: 'fail', detail: t('pages.emailDnsPosture.status_no_record') }
      const p = (s.policy || '').toLowerCase()
      if (p === 'reject') return { state: 'pass', detail: `p=reject${s.pct < 100 ? ` · ${s.pct}%` : ''}` }
      if (p === 'quarantine') return { state: 'warn', detail: `p=quarantine${s.pct < 100 ? ` · ${s.pct}%` : ''}` }
      return { state: 'fail', detail: `p=${p || 'none'}` }
    }
    case 'mta_sts': {
      const tr = d.transport || {}
      if (!tr.mta_sts) return { state: 'warn', detail: t('pages.emailDnsPosture.status_absent') }
      return { state: tr.mta_sts_mode === 'enforce' ? 'pass' : 'warn', detail: tr.mta_sts_mode || t('pages.emailDnsPosture.status_present') }
    }
    case 'tls_rpt': {
      const tr = d.transport || {}
      return tr.tls_rpt ? { state: 'pass', detail: t('pages.emailDnsPosture.status_present') } : { state: 'warn', detail: t('pages.emailDnsPosture.status_absent') }
    }
    case 'smtp_tls': {
      const tr = d.transport || {}
      if (!tr.smtp_checked) return { state: 'unknown', detail: t('pages.emailDnsPosture.status_not_checked') }
      if (!tr.smtp_reachable) return { state: 'unknown', detail: t('pages.emailDnsPosture.status_unreachable') }
      return tr.smtp_starttls ? { state: 'pass', detail: 'STARTTLS' } : { state: 'fail', detail: t('pages.emailDnsPosture.status_cleartext') }
    }
    case 'dnssec': {
      const v = (d.dns_trust || {}).dnssec
      if (v === null || v === undefined) return { state: 'unknown', detail: t('pages.emailDnsPosture.status_not_checked') }
      return v ? { state: 'pass', detail: t('pages.emailDnsPosture.status_signed') } : { state: 'warn', detail: t('pages.emailDnsPosture.status_unsigned') }
    }
    case 'dane': {
      const v = (d.transport || {}).dane
      if (v === null || v === undefined) return { state: 'unknown', detail: t('pages.emailDnsPosture.status_not_checked') }
      return v ? { state: 'pass', detail: 'TLSA' } : { state: 'warn', detail: t('pages.emailDnsPosture.status_absent') }
    }
    case 'caa': {
      const v = (d.dns_trust || {}).caa
      return v ? { state: 'pass', detail: t('pages.emailDnsPosture.status_present') } : { state: 'warn', detail: t('pages.emailDnsPosture.status_absent') }
    }
    case 'bimi': {
      const dt = d.dns_trust || {}
      if (!dt.bimi) return { state: 'unknown', detail: t('pages.emailDnsPosture.status_absent') }
      return { state: 'pass', detail: dt.bimi_vmc ? 'VMC' : t('pages.emailDnsPosture.status_logo') }
    }
    default:
      return { state: 'unknown', detail: '' }
  }
}

const STATE_STYLE = {
  pass: { sym: '✓', cls: 'border-emerald-500/30 bg-emerald-500/5', text: 'text-emerald-400' },
  warn: { sym: '!', cls: 'border-amber-500/30 bg-amber-500/5', text: 'text-amber-400' },
  fail: { sym: '✕', cls: 'border-rose-500/30 bg-rose-500/5', text: 'text-rose-400' },
  unknown: { sym: '·', cls: 'border-[var(--border-default)] bg-[var(--row-hover-bg)]', text: 'text-[var(--text-muted)]' },
}

function CopyButton({ text }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const onCopy = useCallback(() => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    }).catch(() => {})
  }, [text])
  return (
    <Button variant="unstyled" type="button" onClick={onCopy}
      className="shrink-0 text-[9px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-muted)] hover:text-cyan-300 hover:border-cyan-400/40 transition-colors">
      {copied ? `${t('pages.emailDnsPosture.copy_done')} ✓` : t('pages.emailDnsPosture.copy_action')}
    </Button>
  )
}

function ToxicCombinationsPanel({ combos }) {
  const { t } = useTranslation()
  if (!Array.isArray(combos) || combos.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.toxic_title')}</div>
      <div className="space-y-2">
        {combos.map((c, i) => {
          const sev = (c.severity || 'medium').toLowerCase()
          const st = TOXIC_STYLE[sev] || TOXIC_STYLE.medium
          return (
            <div key={c.id || i} className={`rounded-xl border ${st.bd} ${st.bg} px-3 py-2.5`}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-[10px] font-mono uppercase ${st.text}`}>{sev}</span>
                <span className="text-sm font-medium text-[var(--text-primary)]">{c.title}</span>
              </div>
              {c.attack_path && <p className="text-[11px] font-mono text-[var(--text-tertiary)] mt-1">{c.attack_path}</p>}
              {c.impact && <p className="text-[10px] text-[var(--text-muted)] mt-0.5">{t('pages.emailDnsPosture.toxic_impact_label')} {c.impact}</p>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ComplianceMatrix({ compliance }) {
  const { t } = useTranslation()
  if (!compliance || typeof compliance !== 'object') return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.emailDnsPosture.compliance_title')}</div>
        {compliance.overall_pass != null && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${compliance.overall_pass ? 'border-emerald-500/30 text-emerald-400' : 'border-rose-500/30 text-rose-400'}`}>
            {compliance.overall_pass ? t('pages.emailDnsPosture.compliance_overall_pass') : t('pages.emailDnsPosture.compliance_gaps_remain')}
          </span>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {COMPLIANCE_KEYS.map((g) => {
          const src = g.group.startsWith('NIST') ? compliance.nist_sp_800_53
            : g.group.startsWith('CIS') ? compliance.cis_controls_v8
              : { gdpr_art_32: compliance.gdpr_art_32, nis2_email_security: compliance.nis2_email_security }
          return (
            <div key={g.group} className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-2.5">
              <div className="text-[10px] font-mono text-[var(--text-tertiary)] mb-1.5">{t(g.groupKey)}</div>
              <div className="space-y-1">
                {g.keys.map(([k, label]) => {
                  const pass = src?.[k] === true
                  return (
                    <div key={k} className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-[var(--text-tertiary)]">{t(label)}</span>
                      <span className={pass ? 'text-emerald-400' : 'text-rose-400'}>{pass ? '✓' : '✕'}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SpfBlastPanel({ blast }) {
  const { t } = useTranslation()
  if (!blast || !Array.isArray(blast.vendors) || blast.vendors.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">
        {t('pages.emailDnsPosture.spf_blast_title', { count: blast.count || blast.vendors.length })}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {blast.vendors.map((v, i) => (
          <span key={i} title={v.domain} className={`text-[10px] font-mono px-2 py-1 rounded border ${v.reachable ? 'border-cyan-500/30 bg-cyan-500/5 text-cyan-200' : 'border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-muted)]'}`}>
            {v.vendor || v.domain}
          </span>
        ))}
      </div>
    </div>
  )
}

function AutodiscoverPanel({ data }) {
  const { t } = useTranslation()
  if (!data?.checked) return null
  const surface = Array.isArray(data.surface) ? data.surface : []
  if (surface.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.autodiscover_title')}</div>
      <div className="flex flex-wrap gap-1.5 mb-2">
        {surface.map((s) => (
          <span key={s} className="text-[10px] font-mono px-2 py-1 rounded border border-violet-500/30 bg-violet-500/5 text-violet-200">{s}</span>
        ))}
      </div>
      {data.cname && <p className="text-[10px] font-mono text-[var(--text-muted)]">CNAME → {data.cname}</p>}
    </div>
  )
}

function DmarcExternalPanel({ data }) {
  const { t } = useTranslation()
  if (!data?.checked || !Array.isArray(data.receivers) || data.receivers.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.dmarc_receivers_title')}</div>
      <div className="space-y-1">
        {data.receivers.map((r, i) => (
          <div key={i} className="flex items-center justify-between text-[10px] font-mono px-2 py-1 rounded border border-[var(--border-default)] bg-[var(--row-hover-bg)]">
            <span className="text-[var(--text-tertiary)]">{r.receiver}</span>
            <span className={r.authorized ? 'text-emerald-400' : 'text-rose-400'}>{r.internal ? t('pages.emailDnsPosture.dmarc_receiver_in_domain') : r.authorized ? t('pages.emailDnsPosture.dmarc_receiver_authorized') : t('pages.emailDnsPosture.dmarc_receiver_missing')}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SmtpAuditPanel({ audit }) {
  const { t } = useTranslation()
  const probes = audit?.probes
  if (!Array.isArray(probes) || probes.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.smtp_probes_title')}</div>
      <div className="space-y-1.5">
        {probes.map((p, i) => (
          <div key={i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-2.5 py-1.5 text-[10px] font-mono">
            <div className="flex justify-between text-[var(--text-secondary)]"><span>{p.host}:{p.port}</span><span className={p.starttls ? 'text-emerald-400' : 'text-amber-400'}>{p.starttls ? 'STARTTLS' : t('pages.emailDnsPosture.smtp_no_tls')}</span></div>
            {p.banner && <div className="text-[var(--text-muted)] truncate mt-0.5">{p.banner}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

function SpfIpInventoryPanel({ inv }) {
  const { t } = useTranslation()
  if (!inv?.checked) return null
  const v4 = inv.ipv4_count ?? 0
  const v6 = inv.ipv6_count ?? 0
  if (v4 === 0 && v6 === 0 && !inv.world_open) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.spf_ip_title')}</div>
      <div className="flex flex-wrap gap-2 text-[10px] font-mono mb-2">
        <span className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/5 text-cyan-200">{v4} IPv4</span>
        <span className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/5 text-cyan-200">{v6} IPv6</span>
        {inv.resolved_from_amx > 0 && <span className="text-[var(--text-muted)]">{t('pages.emailDnsPosture.spf_ip_from_amx', { count: inv.resolved_from_amx })}</span>}
        {inv.world_open && <span className="text-rose-400 font-bold">⚠ {t('pages.emailDnsPosture.spf_ip_world_open')}</span>}
      </div>
      {Array.isArray(inv.ipv4_sample) && inv.ipv4_sample.length > 0 && (
        <p className="text-[10px] font-mono text-[var(--text-muted)] truncate">v4: {inv.ipv4_sample.join(', ')}</p>
      )}
    </div>
  )
}

function MxTlsCertsPanel({ data }) {
  const { t } = useTranslation()
  if (!data?.checked || !Array.isArray(data.certs) || data.certs.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.mx_certs_title')}</div>
      <div className="space-y-1.5">
        {data.certs.map((c, i) => (
          <div key={i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-2.5 py-1.5 text-[10px] font-mono">
            <div className="flex justify-between text-[var(--text-secondary)]"><span>{c.host}:{c.port}</span><span className={c.expired ? 'text-rose-400' : c.days_until_expiry < 30 ? 'text-amber-400' : 'text-emerald-400'}>{c.expired ? t('pages.emailDnsPosture.cert_expired') : `${c.days_until_expiry}d`}</span></div>
            <div className="text-[var(--text-muted)] truncate">{c.issuer}</div>
            <div className="flex flex-wrap gap-2 mt-0.5 text-[var(--text-muted)]">
              <span>{t('pages.emailDnsPosture.cert_bits', { bits: c.public_key_bits })}</span>
              <span>{c.san_match ? t('pages.emailDnsPosture.cert_san_ok') : t('pages.emailDnsPosture.cert_san_mismatch')}</span>
              {c.tls_version && <span className={/^TLSv1\.[01]/i.test(c.tls_version) ? 'text-rose-400' : 'text-emerald-400/80'}>{c.tls_version}</span>}
              {c.self_signed && <span className="text-rose-400">{t('pages.emailDnsPosture.cert_self_signed')}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const MANIFEST_STATUS = {
  pass: { sym: '✓', cls: 'border-emerald-500/30 bg-emerald-500/5', text: 'text-emerald-300' },
  warn: { sym: '⚠', cls: 'border-amber-500/30 bg-amber-500/5', text: 'text-amber-300' },
  fail: { sym: '✗', cls: 'border-rose-500/30 bg-rose-500/5', text: 'text-rose-300' },
  skipped: { sym: '—', cls: 'border-[var(--border-default)] bg-[var(--row-hover-bg)]', text: 'text-[var(--text-muted)]' },
}

function CoverageManifestPanel({ manifest, catalog }) {
  const { t } = useTranslation()
  if (!manifest?.probes?.length) return null
  const tier = manifest.posture_tier || 'baseline'
  const pct = manifest.completeness_pct ?? 0
  const tierColor = { enterprise: '#34d399', advanced: '#a3e635', standard: '#fbbf24', baseline: '#fb923c' }[tier] || '#94a3b8'
  const layers = catalog?.probe_layers ?? catalog?.categories?.length
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
          {t('pages.emailDnsPosture.coverage_title')}
          {catalog?.version && <span className="text-[var(--text-disabled)] normal-case ml-2">v{catalog.version}{layers ? ` · ${t('pages.emailDnsPosture.coverage_layers', { count: layers })}` : ''}</span>}
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <span className="text-[var(--text-tertiary)]">{t('pages.emailDnsPosture.coverage_passing', { passing: manifest.probes_passing, count: manifest.probe_count })}</span>
          <span style={{ color: tierColor }} className="uppercase tracking-wider">{tier}</span>
          <span className="text-[var(--text-secondary)]">{pct}%</span>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-1.5">
        {manifest.probes.map((p) => {
          const st = MANIFEST_STATUS[p.status] || MANIFEST_STATUS.skipped
          return (
            <div key={p.id} className={`rounded-lg border px-2 py-1.5 ${st.cls}`} title={p.standard}>
              <div className="flex items-center justify-between gap-1">
                <span className="text-[10px] font-mono text-[var(--text-secondary)] truncate">{p.name}</span>
                <span className={`${st.text} text-xs shrink-0`}>{st.sym}</span>
              </div>
              <div className="text-[8px] font-mono text-[var(--text-disabled)] truncate">{p.standard}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function TlsRptPanel({ data }) {
  const { t } = useTranslation()
  if (!data?.present) return null
  return (
    <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.tls_rpt_title')}</div>
      <div className="text-[10px] font-mono text-[var(--text-tertiary)]">
        {(data.rua_uris || []).length > 0 ? data.rua_uris.join(', ') : t('pages.emailDnsPosture.tls_rpt_no_rua')}
      </div>
    </div>
  )
}

function SubScoreBar({ label, value }) {
  const v = Math.max(0, Math.min(100, Number(value) || 0))
  const color = v >= 85 ? '#34d399' : v >= 60 ? '#a3e635' : v >= 40 ? '#fbbf24' : '#fb7185'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-mono text-[var(--text-tertiary)]">{label}</span>
        <span className="text-[10px] font-mono" style={{ color }}>{v}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

function Scorecard({ summary }) {
  const { t } = useTranslation()
  if (!summary) return null
  const score = summary.score ?? 0
  const grade = summary.grade || '—'
  const color = gradeColor(grade)
  const spoof = SPOOF_STYLE[summary.spoofability] || SPOOF_STYLE.spoofable
  const subscores = summary.subscores || {}
  const details = summary.details || {}
  const roadmap = Array.isArray(summary.roadmap) ? summary.roadmap : []
  const toxic = Array.isArray(summary.toxic_combinations) ? summary.toxic_combinations : []
  const compliance = summary.compliance || null
  const spfBlast = summary.spf_blast_radius || null
  const consensus = summary.resolver_consensus || null
  const autodiscover = summary.autodiscover || null
  const dmarcExternal = summary.dmarc_external_reports || null
  const smtpAudit = summary.smtp_audit || null
  const spfIpInv = summary.spf_ip_inventory || null
  const mxTlsCerts = summary.mx_tls_certs || null
  const tlsRptDetails = summary.tls_rpt_details || null
  const mtaStsDrift = summary.mta_sts_mx_drift || null
  const coverageManifest = summary.coverage_manifest || null
  const probeCatalog = summary.probe_catalog || null
  const soaPosture = summary.soa_posture || null

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Grade gauge */}
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold" style={{ color }}>{score}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.emailDnsPosture.trust_grade')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="text-[11px] font-mono text-[var(--text-muted)] mt-1">{summary.analyzed_domain || summary.target}</div>
            {summary.provider && (
              <div className="mt-1.5 inline-flex items-center gap-1 text-[10px] font-mono text-[var(--text-tertiary)] px-2 py-0.5 rounded-md bg-[var(--row-hover-bg)] border border-[var(--border-default)]">
                ✉ {summary.provider}
              </div>
            )}
          </div>
        </div>

        {/* Sub-scores */}
        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5 content-center">
          {SUBSCORES.map((s) => (
            <SubScoreBar key={s.key} label={t(s.labelKey)} value={subscores[s.key]} />
          ))}
        </div>
      </div>

      {/* Spoofability verdict — the headline toxic-combination insight */}
      <div className={`mt-5 rounded-xl border ${spoof.bd} ${spoof.bg} px-4 py-3`}>
        <div className="flex items-center gap-2">
          <span className="text-lg" style={{ color: spoof.color }}>{spoof.icon}</span>
          <span className="text-sm font-bold" style={{ color: spoof.color }}>{t('pages.emailDnsPosture.spoofability_label')} {t(spoof.labelKey)}</span>
        </div>
        {summary.spoofability_reason && (
          <p className="text-[12px] text-[var(--text-tertiary)] font-mono leading-relaxed mt-1.5">{summary.spoofability_reason}</p>
        )}
      </div>

      {/* Toxic combinations — Wiz-style multi-control attack paths */}
      <ToxicCombinationsPanel combos={toxic} />

      <SpfBlastPanel blast={spfBlast} />
      <SpfIpInventoryPanel inv={spfIpInv} />

      <ComplianceMatrix compliance={compliance} />

      <CoverageManifestPanel manifest={coverageManifest} catalog={probeCatalog} />

      {consensus?.checked && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.consensus_title')}</div>
          <div className={`text-[11px] font-mono px-3 py-2 rounded-lg border ${consensus.consensus ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-rose-500/30 bg-rose-500/5 text-rose-300'}`}>
            {consensus.consensus
              ? t('pages.emailDnsPosture.consensus_agree')
              : t('pages.emailDnsPosture.consensus_mismatch', { details: (consensus.mismatches || []).join('; ') })}
          </div>
        </div>
      )}

      <AutodiscoverPanel data={autodiscover} />
      <DmarcExternalPanel data={dmarcExternal} />
      <SmtpAuditPanel audit={smtpAudit} />
      <MxTlsCertsPanel data={mxTlsCerts} />
      <TlsRptPanel data={tlsRptDetails} />

      {mtaStsDrift?.checked && Array.isArray(mtaStsDrift.missing_from_policy) && mtaStsDrift.missing_from_policy.length > 0 && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400/80 mb-2">{t('pages.emailDnsPosture.mta_sts_drift_title')}</div>
          <p className="text-[11px] font-mono text-[var(--text-tertiary)]">{t('pages.emailDnsPosture.mta_sts_drift_body', { hosts: mtaStsDrift.missing_from_policy.join(', ') })}</p>
        </div>
      )}

      {soaPosture?.checked && soaPosture.minimum_ttl != null && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.soa_title')}</div>
          <p className="text-[11px] font-mono text-[var(--text-tertiary)]">{soaPosture.minimum_ttl}s — {soaPosture.record || t('pages.emailDnsPosture.soa_no_record')}</p>
        </div>
      )}

      {/* Per-standard status grid */}
      <div className="mt-5">
        <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.control_coverage')}</div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-1.5">
          {STANDARDS.map((std) => {
            const st = standardStatus(details, std.key, t)
            const style = STATE_STYLE[st.state] || STATE_STYLE.unknown
            return (
              <div key={std.key} className={`rounded-lg border px-2.5 py-1.5 ${style.cls}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-[var(--text-secondary)]">{std.label}</span>
                  <span className={`${style.text} text-xs`}>{style.sym}</span>
                </div>
                <div className="text-[9px] font-mono text-[var(--text-muted)] mt-0.5 truncate">{st.detail}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Remediation roadmap */}
      {roadmap.length > 0 && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.roadmap_title')}</div>
          <ol className="space-y-1.5">
            {roadmap.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">
                <span className="text-cyan-400 shrink-0">{i + 1}.</span>{r}
              </li>
            ))}
          </ol>
        </div>
      )}
    </motion.div>
  )
}

function FindingCard({ f }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const refs = Array.isArray(f.references) ? f.references : []
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.standard && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)] border border-[var(--border-default)]">{f.standard}</span>}
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
            {f.cwe && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.cwe}</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            {f.evidence && (
              <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-2.5">
                <div className="text-[9px] font-mono uppercase text-[var(--text-disabled)] mb-1">{t('pages.emailDnsPosture.finding_observed')}</div>
                <code className="text-[11px] font-mono text-[var(--text-secondary)] break-all">{f.evidence}</code>
              </div>
            )}
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">{t('pages.emailDnsPosture.finding_remediation')}</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {f.recommended_record && (
              <div className="mt-2 rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-2.5">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase text-cyan-400/70">{t('pages.emailDnsPosture.finding_dns_record')}</span>
                  <CopyButton text={f.recommended_record} />
                </div>
                <code className="text-[11px] font-mono text-cyan-100/85 break-all">{f.recommended_record}</code>
              </div>
            )}
            {refs.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {refs.map((c) => (
                  <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)] border border-[var(--border-default)]">{c}</span>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function EmailDnsPosture() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [showParams, setShowParams] = useState(false)
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [toast, setToast] = useState(null)

  const issues = useMemo(
    () => findings.filter((f) => !isSummary(f)).sort((a, b) => sevValue((b.severity || '').toLowerCase()) - sevValue((a.severity || '').toLowerCase())),
    [findings],
  )

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    refreshFromHistory,
    historyLoading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
  } = useWeissmanEnginePage(ENGINE, issues)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  // Parameters (1:1 with the engine's job_params).
  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [resolver, setResolver] = useState('system')
  const [dkimSelectors, setDkimSelectors] = useState('')
  const [smtpPorts, setSmtpPorts] = useState('25,465,587')
  const [minDkimBits, setMinDkimBits] = useState(2048)
  const [spfLookupLimit, setSpfLookupLimit] = useState(10)
  const [timeoutMs, setTimeoutMs] = useState(5000)
  const [mailSubdomains, setMailSubdomains] = useState('')

  useEffect(() => {
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  const selectedClient = useMemo(() => clients.find((c) => String(c.id) === String(clientId)), [clients, clientId])
  useEffect(() => { if (!targetTouched) setTarget(firstClientTarget(selectedClient)) }, [selectedClient, targetTouched])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((x) => (x?.id === id ? null : x)), 5000)
  }, [])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (job?.id) setLastJobId(String(job.id))
      setPendingJobId(null)
    },
  })

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: target.trim(),
      ...toggles,
      resolver,
      smtp_ports: smtpPorts.trim() || '25,465,587',
      min_dkim_bits: Number(minDkimBits) || 2048,
      spf_lookup_limit: Number(spfLookupLimit) || 10,
      timeout_ms: Number(timeoutMs) || 5000,
    }
    if (clientId) body.client_id = Number(clientId)
    if (dkimSelectors.trim()) body.dkim_selectors = dkimSelectors.trim()
    if (mailSubdomains.trim()) body.mail_subdomains = mailSubdomains.trim()
    return body
  }, [target, toggles, resolver, smtpPorts, minDkimBits, spfLookupLimit, timeoutMs, clientId, dkimSelectors, mailSubdomains])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.emailDnsPosture.toast_select_client')); return }
    if (!target.trim()) { showToast('error', t('pages.emailDnsPosture.toast_target_required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.emailDnsPosture.toast_scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.emailDnsPosture.toast_scan_queued', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.emailDnsPosture.toast_scan_failed'))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.emailDnsPosture.page_title')}
      badge="SPF / DKIM / DMARC / MTA-STS / BIMI"
      badgeColor={ACCENT}
      subtitle={t('pages.emailDnsPosture.page_subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={status === 'running'}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-emerald-500/30 text-emerald-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.emailDnsPosture.label_client')}</label>
            <BoundClientScanField
              clients={clients}
              selectedClientId={clientId}
              onChange={(id) => { setClientId(id || ''); setTargetTouched(false) }}
              emptyLabel={t('pages.emailDnsPosture.select_client_placeholder')}
            />
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.emailDnsPosture.label_target_domain')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #22d3ee' : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t(`pages.emailDnsPosture.state_${status}`, status)}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-emerald-500/40 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? `⟳ ${t('pages.emailDnsPosture.btn_scanning')}` : `▶ ${t('pages.emailDnsPosture.btn_run_scan')}`}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-all">
            {showParams ? '▾' : '▸'} {t('pages.emailDnsPosture.params_label')}
          </Button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.emailDnsPosture.probe_categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={t(tg.hintKey)} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-emerald-500" />
                        {t(tg.labelKey)}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.dns_resolver')}</label>
                    <select value={resolver} onChange={(e) => setResolver(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40">
                      {['system', 'cloudflare', 'google', 'quad9'].map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.extra_dkim_selectors')}</label>
                    <input type="text" value={dkimSelectors} onChange={(e) => setDkimSelectors(e.target.value)} placeholder="selector1, google, k1"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.smtp_ports')}</label>
                    <input type="text" value={smtpPorts} onChange={(e) => setSmtpPorts(e.target.value)} placeholder="25,465,587"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.mail_subdomains')}</label>
                    <input type="text" value={mailSubdomains} onChange={(e) => setMailSubdomains(e.target.value)} placeholder="mail,autodiscover,webmail"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.min_dkim_bits')}</label>
                      <input type="number" min="1024" max="4096" step="1024" value={minDkimBits} onChange={(e) => setMinDkimBits(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.spf_lookup_limit')}</label>
                      <input type="number" min="1" max="20" step="1" value={spfLookupLimit} onChange={(e) => setSpfLookupLimit(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.emailDnsPosture.per_probe_timeout')}</label>
                    <input type="number" min="1000" max="20000" step="500" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.emailDnsPosture.last_completed', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.emailDnsPosture.select_client_prompt')}
        </div>
      )}

      <Scorecard summary={summary} />

      <WeissmanFindingsPanel
        findings={issues}
        filteredFindings={filteredFindings}
        counts={counts}
        total={issues.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && issues.length === 0}
        loading={historyLoading && issues.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        showEmptyReady={status !== 'running' && issues.length === 0}
        emptyReadyTitle={t('pages.emailDnsPosture.empty_ready_title')}
        emptyReadyBody={t('pages.emailDnsPosture.empty_ready_body')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
