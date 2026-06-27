import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

// Command Center GUI for the `email_dns_posture` engine — Email & Domain Trust Posture.
// Every control maps 1:1 to a real engine parameter consumed from the scan body via job_params.
const ENGINE = 'email_dns_posture'
const ACCENT = '#34d399'

const TOGGLES = [
  { key: 'check_smtp_tls', label: 'SMTP STARTTLS probe', hint: 'Live EHLO/STARTTLS capability probe against MX hosts (degrades if port 25 is blocked)', defaultVal: true },
  { key: 'check_mta_sts', label: 'MTA-STS (DNS + HTTPS policy)', hint: 'Fetches the HTTPS .well-known/mta-sts.txt policy and validates mode', defaultVal: true },
  { key: 'check_dnssec', label: 'DNSSEC', hint: 'DNSKEY / DS presence (best-effort)', defaultVal: true },
  { key: 'check_caa', label: 'CAA issuance control', hint: 'Certificate-authority authorization records', defaultVal: true },
  { key: 'check_bimi', label: 'BIMI (brand logo)', hint: 'Verified-logo + VMC presence (requires enforced DMARC)', defaultVal: true },
  { key: 'check_dane', label: 'DANE / TLSA', hint: 'TLSA records for inbound SMTP (requires DNSSEC)', defaultVal: false },
  { key: 'check_resolver_consensus', label: 'Resolver consensus (SPF/DMARC/MX)', hint: 'Cross-check system vs Cloudflare/Google/Quad9 for split-horizon or poisoning', defaultVal: true },
  { key: 'check_mail_subdomains', label: 'Mail subdomain blast-radius', hint: 'Probe mail., autodiscover., etc. for SPF/DMARC gaps on live surfaces', defaultVal: true },
  { key: 'check_autodiscover', label: 'Autodiscover surface (CNAME/SRV/HTTPS)', hint: 'Microsoft autodiscover.xml + Mozilla autoconfig + SRV records', defaultVal: true },
  { key: 'check_bimi_logo_fetch', label: 'BIMI logo HTTPS fetch', hint: 'Live fetch of BIMI l= logo URL — content-type and reachability', defaultVal: true },
  { key: 'check_dmarc_external_reports', label: 'DMARC external report authorization', hint: 'RFC 7489 _report._dmarc.* checks on third-party report receivers', defaultVal: true },
  { key: 'check_mx_diversity', label: 'Mixed MX provider detection', hint: 'Flag split-routing across multiple mail SaaS providers', defaultVal: true },
  { key: 'check_spf_ip_inventory', label: 'SPF IP flatten inventory', hint: 'Expand ip4/ip6/a/mx into authorized-IP blast-radius count', defaultVal: true },
  { key: 'check_mx_tls_cert', label: 'MX STARTTLS certificate probe', hint: 'Live cert fetch on port 25/587 — expiry, SAN, key size', defaultVal: true },
  { key: 'check_mta_sts_mx_drift', label: 'MTA-STS MX drift check', hint: 'Compare live MX hostnames vs policy mx: allow-list', defaultVal: true },
  { key: 'check_ns_posture', label: 'Authoritative NS redundancy', hint: 'Single nameserver / DNS SPOF detection', defaultVal: true },
  { key: 'check_soa_posture', label: 'SOA minimum TTL posture', hint: 'Negative-cache TTL window for DNS poisoning against mail-trust records', defaultVal: true },
  { key: 'check_bimi_vmc_fetch', label: 'BIMI VMC HTTPS fetch', hint: 'Live fetch + PEM validation of Verified Mark Certificate URL', defaultVal: true },
  { key: 'subdomain_policy_required', label: 'Require DMARC sp=', hint: 'Treat a missing/weak subdomain policy as a gap', defaultVal: true },
  { key: 'strict_mode', label: 'Strict mode', hint: 'Escalate severities (treat warnings as failures)', defaultVal: false },
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
  { group: 'NIST SP 800-53', keys: [['SI-10', 'Email auth'], ['SC-8', 'TLS in transit'], ['SC-20', 'DNSSEC'], ['AU-6', 'DMARC rua']] },
  { group: 'CIS v8', keys: [['9_5', 'SPF'], ['9_6', 'DMARC'], ['9_7', 'DKIM']] },
  { group: 'Regulatory', keys: [['gdpr_art_32', 'GDPR Art.32'], ['nis2_email_security', 'NIS2 email']] },
]

const TOXIC_STYLE = {
  critical: { bd: 'border-rose-500/40', bg: 'bg-rose-500/10', text: 'text-rose-300' },
  high: { bd: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-300' },
  medium: { bd: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-300' },
  low: { bd: 'border-sky-500/40', bg: 'bg-sky-500/10', text: 'text-sky-300' },
}

const SUBSCORES = [
  { key: 'spf', label: 'SPF' },
  { key: 'dmarc', label: 'DMARC' },
  { key: 'dkim', label: 'DKIM' },
  { key: 'transport', label: 'Transport TLS' },
  { key: 'dns_trust', label: 'DNS Trust' },
]

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-slate-300', bd: 'border-white/10', bg: 'bg-white/5', dot: '#94a3b8' },
}

const SPOOF_STYLE = {
  protected: { color: '#34d399', bg: 'bg-emerald-500/10', bd: 'border-emerald-500/30', icon: '🛡', label: 'Protected' },
  partial: { color: '#fbbf24', bg: 'bg-amber-500/10', bd: 'border-amber-500/30', icon: '⚠', label: 'Partially protected' },
  spoofable: { color: '#fb7185', bg: 'bg-rose-500/10', bd: 'border-rose-500/30', icon: '☠', label: 'Spoofable' },
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
function standardStatus(details, key) {
  if (!details) return { state: 'unknown', detail: '' }
  const d = details
  switch (key) {
    case 'spf': {
      const s = d.spf || {}
      if (!s.present) return { state: 'fail', detail: 'no record' }
      const q = s.qualifier
      const good = (q === '-' || q === '~') && !s.over_limit
      return { state: good ? 'pass' : 'warn', detail: `${q ? `${q}all` : 'neutral'}${s.over_limit ? ' · >10 lookups' : ''}` }
    }
    case 'dkim': {
      const s = d.dkim || {}
      const n = Array.isArray(s.selectors_found) ? s.selectors_found.length : 0
      if (n === 0 && !s.ed25519) return { state: 'warn', detail: 'none found' }
      return { state: 'pass', detail: `${n} selector${n === 1 ? '' : 's'}${s.min_key_bits ? ` · ${s.min_key_bits}-bit` : ''}` }
    }
    case 'dmarc': {
      const s = d.dmarc || {}
      if (!s.present) return { state: 'fail', detail: 'no record' }
      const p = (s.policy || '').toLowerCase()
      if (p === 'reject') return { state: 'pass', detail: `p=reject${s.pct < 100 ? ` · ${s.pct}%` : ''}` }
      if (p === 'quarantine') return { state: 'warn', detail: `p=quarantine${s.pct < 100 ? ` · ${s.pct}%` : ''}` }
      return { state: 'fail', detail: `p=${p || 'none'}` }
    }
    case 'mta_sts': {
      const tr = d.transport || {}
      if (!tr.mta_sts) return { state: 'warn', detail: 'absent' }
      return { state: tr.mta_sts_mode === 'enforce' ? 'pass' : 'warn', detail: tr.mta_sts_mode || 'present' }
    }
    case 'tls_rpt': {
      const tr = d.transport || {}
      return tr.tls_rpt ? { state: 'pass', detail: 'present' } : { state: 'warn', detail: 'absent' }
    }
    case 'smtp_tls': {
      const tr = d.transport || {}
      if (!tr.smtp_checked) return { state: 'unknown', detail: 'not checked' }
      if (!tr.smtp_reachable) return { state: 'unknown', detail: 'unreachable' }
      return tr.smtp_starttls ? { state: 'pass', detail: 'STARTTLS' } : { state: 'fail', detail: 'cleartext' }
    }
    case 'dnssec': {
      const v = (d.dns_trust || {}).dnssec
      if (v === null || v === undefined) return { state: 'unknown', detail: 'not checked' }
      return v ? { state: 'pass', detail: 'signed' } : { state: 'warn', detail: 'unsigned' }
    }
    case 'dane': {
      const v = (d.transport || {}).dane
      if (v === null || v === undefined) return { state: 'unknown', detail: 'not checked' }
      return v ? { state: 'pass', detail: 'TLSA' } : { state: 'warn', detail: 'absent' }
    }
    case 'caa': {
      const v = (d.dns_trust || {}).caa
      return v ? { state: 'pass', detail: 'present' } : { state: 'warn', detail: 'absent' }
    }
    case 'bimi': {
      const dt = d.dns_trust || {}
      if (!dt.bimi) return { state: 'unknown', detail: 'absent' }
      return { state: 'pass', detail: dt.bimi_vmc ? 'VMC' : 'logo' }
    }
    default:
      return { state: 'unknown', detail: '' }
  }
}

const STATE_STYLE = {
  pass: { sym: '✓', cls: 'border-emerald-500/30 bg-emerald-500/5', text: 'text-emerald-400' },
  warn: { sym: '!', cls: 'border-amber-500/30 bg-amber-500/5', text: 'text-amber-400' },
  fail: { sym: '✕', cls: 'border-rose-500/30 bg-rose-500/5', text: 'text-rose-400' },
  unknown: { sym: '·', cls: 'border-white/10 bg-white/5', text: 'text-white/40' },
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const onCopy = useCallback(() => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }, [text])
  return (
    <button type="button" onClick={onCopy}
      className="shrink-0 text-[9px] font-mono px-1.5 py-0.5 rounded border border-white/15 text-white/40 hover:text-cyan-300 hover:border-cyan-400/40 transition-colors">
      {copied ? 'copied ✓' : 'copy'}
    </button>
  )
}

function ToxicCombinationsPanel({ combos }) {
  if (!Array.isArray(combos) || combos.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Toxic combinations — attack paths</div>
      <div className="space-y-2">
        {combos.map((c, i) => {
          const sev = (c.severity || 'medium').toLowerCase()
          const st = TOXIC_STYLE[sev] || TOXIC_STYLE.medium
          return (
            <div key={c.id || i} className={`rounded-xl border ${st.bd} ${st.bg} px-3 py-2.5`}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-[10px] font-mono uppercase ${st.text}`}>{sev}</span>
                <span className="text-sm font-medium text-white/90">{c.title}</span>
              </div>
              {c.attack_path && <p className="text-[11px] font-mono text-white/55 mt-1">{c.attack_path}</p>}
              {c.impact && <p className="text-[10px] text-white/40 mt-0.5">Impact: {c.impact}</p>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ComplianceMatrix({ compliance }) {
  if (!compliance || typeof compliance !== 'object') return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-white/40">Compliance mapping</div>
        {compliance.overall_pass != null && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${compliance.overall_pass ? 'border-emerald-500/30 text-emerald-400' : 'border-rose-500/30 text-rose-400'}`}>
            {compliance.overall_pass ? 'overall pass' : 'gaps remain'}
          </span>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {COMPLIANCE_KEYS.map((g) => {
          const src = g.group.startsWith('NIST') ? compliance.nist_sp_800_53
            : g.group.startsWith('CIS') ? compliance.cis_controls_v8
              : { gdpr_art_32: compliance.gdpr_art_32, nis2_email_security: compliance.nis2_email_security }
          return (
            <div key={g.group} className="rounded-lg border border-white/10 bg-white/5 p-2.5">
              <div className="text-[10px] font-mono text-white/50 mb-1.5">{g.group}</div>
              <div className="space-y-1">
                {g.keys.map(([k, label]) => {
                  const pass = src?.[k] === true
                  return (
                    <div key={k} className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-white/60">{label}</span>
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
  if (!blast || !Array.isArray(blast.vendors) || blast.vendors.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">
        SPF third-party blast radius ({blast.count || blast.vendors.length} authorizers)
      </div>
      <div className="flex flex-wrap gap-1.5">
        {blast.vendors.map((v, i) => (
          <span key={i} title={v.domain} className={`text-[10px] font-mono px-2 py-1 rounded border ${v.reachable ? 'border-cyan-500/30 bg-cyan-500/5 text-cyan-200' : 'border-white/10 bg-white/5 text-white/40'}`}>
            {v.vendor || v.domain}
          </span>
        ))}
      </div>
    </div>
  )
}

function AutodiscoverPanel({ data }) {
  if (!data?.checked) return null
  const surface = Array.isArray(data.surface) ? data.surface : []
  if (surface.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Autodiscover / client config surface</div>
      <div className="flex flex-wrap gap-1.5 mb-2">
        {surface.map((s) => (
          <span key={s} className="text-[10px] font-mono px-2 py-1 rounded border border-violet-500/30 bg-violet-500/5 text-violet-200">{s}</span>
        ))}
      </div>
      {data.cname && <p className="text-[10px] font-mono text-white/45">CNAME → {data.cname}</p>}
    </div>
  )
}

function DmarcExternalPanel({ data }) {
  if (!data?.checked || !Array.isArray(data.receivers) || data.receivers.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">DMARC report receivers</div>
      <div className="space-y-1">
        {data.receivers.map((r, i) => (
          <div key={i} className="flex items-center justify-between text-[10px] font-mono px-2 py-1 rounded border border-white/10 bg-white/5">
            <span className="text-white/65">{r.receiver}</span>
            <span className={r.authorized ? 'text-emerald-400' : 'text-rose-400'}>{r.internal ? 'in-domain' : r.authorized ? 'authorized' : 'missing _report._dmarc'}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SmtpAuditPanel({ audit }) {
  const probes = audit?.probes
  if (!Array.isArray(probes) || probes.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">SMTP live probes</div>
      <div className="space-y-1.5">
        {probes.map((p, i) => (
          <div key={i} className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-[10px] font-mono">
            <div className="flex justify-between text-white/70"><span>{p.host}:{p.port}</span><span className={p.starttls ? 'text-emerald-400' : 'text-amber-400'}>{p.starttls ? 'STARTTLS' : 'no TLS'}</span></div>
            {p.banner && <div className="text-white/40 truncate mt-0.5">{p.banner}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

function SpfIpInventoryPanel({ inv }) {
  if (!inv?.checked) return null
  const v4 = inv.ipv4_count ?? 0
  const v6 = inv.ipv6_count ?? 0
  if (v4 === 0 && v6 === 0 && !inv.world_open) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">SPF authorized IP surface</div>
      <div className="flex flex-wrap gap-2 text-[10px] font-mono mb-2">
        <span className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/5 text-cyan-200">{v4} IPv4</span>
        <span className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/5 text-cyan-200">{v6} IPv6</span>
        {inv.resolved_from_amx > 0 && <span className="text-white/40">{inv.resolved_from_amx} from live a/mx</span>}
        {inv.world_open && <span className="text-rose-400 font-bold">⚠ world-open CIDR</span>}
      </div>
      {Array.isArray(inv.ipv4_sample) && inv.ipv4_sample.length > 0 && (
        <p className="text-[10px] font-mono text-white/40 truncate">v4: {inv.ipv4_sample.join(', ')}</p>
      )}
    </div>
  )
}

function MxTlsCertsPanel({ data }) {
  if (!data?.checked || !Array.isArray(data.certs) || data.certs.length === 0) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">MX STARTTLS certificates</div>
      <div className="space-y-1.5">
        {data.certs.map((c, i) => (
          <div key={i} className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-[10px] font-mono">
            <div className="flex justify-between text-white/75"><span>{c.host}:{c.port}</span><span className={c.expired ? 'text-rose-400' : c.days_until_expiry < 30 ? 'text-amber-400' : 'text-emerald-400'}>{c.expired ? 'expired' : `${c.days_until_expiry}d`}</span></div>
            <div className="text-white/40 truncate">{c.issuer}</div>
            <div className="flex flex-wrap gap-2 mt-0.5 text-white/35">
              <span>{c.public_key_bits}-bit</span>
              <span>{c.san_match ? 'SAN ok' : 'SAN mismatch'}</span>
              {c.tls_version && <span className={/^TLSv1\.[01]/i.test(c.tls_version) ? 'text-rose-400' : 'text-emerald-400/80'}>{c.tls_version}</span>}
              {c.self_signed && <span className="text-rose-400">self-signed</span>}
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
  skipped: { sym: '—', cls: 'border-white/10 bg-white/5', text: 'text-white/35' },
}

function CoverageManifestPanel({ manifest, catalog }) {
  if (!manifest?.probes?.length) return null
  const tier = manifest.posture_tier || 'baseline'
  const pct = manifest.completeness_pct ?? 0
  const tierColor = { enterprise: '#34d399', advanced: '#a3e635', standard: '#fbbf24', baseline: '#fb923c' }[tier] || '#94a3b8'
  const layers = catalog?.probe_layers ?? catalog?.categories?.length
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="text-[10px] font-mono uppercase tracking-wider text-white/40">
          Probe coverage manifest
          {catalog?.version && <span className="text-white/25 normal-case ml-2">v{catalog.version}{layers ? ` · ${layers} layers` : ''}</span>}
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <span className="text-white/50">{manifest.probes_passing}/{manifest.probe_count} passing</span>
          <span style={{ color: tierColor }} className="uppercase tracking-wider">{tier}</span>
          <span className="text-white/70">{pct}%</span>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-1.5">
        {manifest.probes.map((p) => {
          const st = MANIFEST_STATUS[p.status] || MANIFEST_STATUS.skipped
          return (
            <div key={p.id} className={`rounded-lg border px-2 py-1.5 ${st.cls}`} title={p.standard}>
              <div className="flex items-center justify-between gap-1">
                <span className="text-[10px] font-mono text-white/75 truncate">{p.name}</span>
                <span className={`${st.text} text-xs shrink-0`}>{st.sym}</span>
              </div>
              <div className="text-[8px] font-mono text-white/30 truncate">{p.standard}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function TlsRptPanel({ data }) {
  if (!data?.present) return null
  return (
    <div className="mt-5 pt-5 border-t border-white/5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">TLS-RPT reporting</div>
      <div className="text-[10px] font-mono text-white/55">
        {(data.rua_uris || []).length > 0 ? data.rua_uris.join(', ') : 'no rua= defined'}
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
        <span className="text-[10px] font-mono text-white/55">{label}</span>
        <span className="text-[10px] font-mono" style={{ color }}>{v}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

function Scorecard({ summary }) {
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
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 mb-6">
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
              <span className="text-[10px] font-mono text-white/40">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">Trust Grade</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="text-[11px] font-mono text-white/40 mt-1">{summary.analyzed_domain || summary.target}</div>
            {summary.provider && (
              <div className="mt-1.5 inline-flex items-center gap-1 text-[10px] font-mono text-white/50 px-2 py-0.5 rounded-md bg-white/5 border border-white/10">
                ✉ {summary.provider}
              </div>
            )}
          </div>
        </div>

        {/* Sub-scores */}
        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5 content-center">
          {SUBSCORES.map((s) => (
            <SubScoreBar key={s.key} label={s.label} value={subscores[s.key]} />
          ))}
        </div>
      </div>

      {/* Spoofability verdict — the headline toxic-combination insight */}
      <div className={`mt-5 rounded-xl border ${spoof.bd} ${spoof.bg} px-4 py-3`}>
        <div className="flex items-center gap-2">
          <span className="text-lg" style={{ color: spoof.color }}>{spoof.icon}</span>
          <span className="text-sm font-bold" style={{ color: spoof.color }}>Spoofability: {spoof.label}</span>
        </div>
        {summary.spoofability_reason && (
          <p className="text-[12px] text-white/65 font-mono leading-relaxed mt-1.5">{summary.spoofability_reason}</p>
        )}
      </div>

      {/* Toxic combinations — Wiz-style multi-control attack paths */}
      <ToxicCombinationsPanel combos={toxic} />

      <SpfBlastPanel blast={spfBlast} />
      <SpfIpInventoryPanel inv={spfIpInv} />

      <ComplianceMatrix compliance={compliance} />

      <CoverageManifestPanel manifest={coverageManifest} catalog={probeCatalog} />

      {consensus?.checked && (
        <div className="mt-5 pt-5 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Resolver consensus</div>
          <div className={`text-[11px] font-mono px-3 py-2 rounded-lg border ${consensus.consensus ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-rose-500/30 bg-rose-500/5 text-rose-300'}`}>
            {consensus.consensus
              ? 'SPF / DMARC / MX agree across public resolvers'
              : `Mismatch detected: ${(consensus.mismatches || []).join('; ')}`}
          </div>
        </div>
      )}

      <AutodiscoverPanel data={autodiscover} />
      <DmarcExternalPanel data={dmarcExternal} />
      <SmtpAuditPanel audit={smtpAudit} />
      <MxTlsCertsPanel data={mxTlsCerts} />
      <TlsRptPanel data={tlsRptDetails} />

      {mtaStsDrift?.checked && Array.isArray(mtaStsDrift.missing_from_policy) && mtaStsDrift.missing_from_policy.length > 0 && (
        <div className="mt-5 pt-5 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400/80 mb-2">MTA-STS MX drift</div>
          <p className="text-[11px] font-mono text-white/55">Live MX not in policy: {mtaStsDrift.missing_from_policy.join(', ')}</p>
        </div>
      )}

      {soaPosture?.checked && soaPosture.minimum_ttl != null && (
        <div className="mt-5 pt-5 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">SOA minimum TTL</div>
          <p className="text-[11px] font-mono text-white/55">{soaPosture.minimum_ttl}s — {soaPosture.record || 'no SOA parsed'}</p>
        </div>
      )}

      {/* Per-standard status grid */}
      <div className="mt-5">
        <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Control coverage</div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-1.5">
          {STANDARDS.map((std) => {
            const st = standardStatus(details, std.key)
            const style = STATE_STYLE[st.state] || STATE_STYLE.unknown
            return (
              <div key={std.key} className={`rounded-lg border px-2.5 py-1.5 ${style.cls}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-white/75">{std.label}</span>
                  <span className={`${style.text} text-xs`}>{style.sym}</span>
                </div>
                <div className="text-[9px] font-mono text-white/40 mt-0.5 truncate">{st.detail}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Remediation roadmap */}
      {roadmap.length > 0 && (
        <div className="mt-5 pt-5 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Prioritised remediation roadmap</div>
          <ol className="space-y-1.5">
            {roadmap.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-white/65 leading-relaxed">
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
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const refs = Array.isArray(f.references) ? f.references : []
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.standard && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/45 border border-white/10">{f.standard}</span>}
            {f.mitre_attack && <span className="text-[10px] font-mono text-white/30">· {f.mitre_attack}</span>}
            {f.cwe && <span className="text-[10px] font-mono text-white/30">· {f.cwe}</span>}
          </div>
          <div className="text-sm text-white/90 font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-white/30 text-xs mt-1">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-white/60 leading-relaxed mt-2">{f.description}</p>
            {f.evidence && (
              <div className="mt-2 rounded-lg bg-black/40 border border-white/5 p-2.5">
                <div className="text-[9px] font-mono uppercase text-white/30 mb-1">Observed</div>
                <code className="text-[11px] font-mono text-white/70 break-all">{f.evidence}</code>
              </div>
            )}
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">Remediation</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {f.recommended_record && (
              <div className="mt-2 rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-2.5">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase text-cyan-400/70">Copy-paste DNS record</span>
                  <CopyButton text={f.recommended_record} />
                </div>
                <code className="text-[11px] font-mono text-cyan-100/85 break-all">{f.recommended_record}</code>
              </div>
            )}
            {refs.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {refs.map((c) => (
                  <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/45 border border-white/10">{c}</span>
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
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
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
    if (!clientId) { showToast('error', 'Select a client first'); return }
    if (!target.trim()) { showToast('error', 'A target domain is required'); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || 'Scan failed'); return }
      const jobId = d.job_id ?? ''
      showToast('info', `Posture scan queued (${jobId})`)
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? 'Scan failed')
    }
  }, [clientId, target, buildBody, showToast])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title="Email & Domain Trust Posture"
      badge="SPF / DKIM / DMARC / MTA-STS / BIMI"
      badgeColor={ACCENT}
      subtitle="World-class anti-spoofing & mail-trust audit — SPF blast-radius, resolver consensus, toxic attack-path synthesis, compliance mapping (NIST/CIS/GDPR/NIS2), subdomain blast-radius, MX FCrDNS, MTA-STS deep parse, BIMI, DNSSEC, DANE & SMTP TLS. Graded A+→F with copy-paste remediation. 100% live, read-only."
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-emerald-500/30 text-emerald-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">Client</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40 min-w-[180px]">
              <option value="">— Select client —</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">Target domain</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="example.com"
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #22d3ee' : 'none' }} />
            <span className="text-[10px] font-mono text-white/40 uppercase">{status}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-emerald-500/40 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? '⟳ Scanning…' : '▶ Run Posture Scan'}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-all">
            {showParams ? '▾ Parameters' : '▸ Parameters'}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-white/5 grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">Probe categories</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-white/70 cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-emerald-500" />
                        {tg.label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">DNS resolver</label>
                    <select value={resolver} onChange={(e) => setResolver(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40">
                      {['system', 'cloudflare', 'google', 'quad9'].map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">Extra DKIM selectors</label>
                    <input type="text" value={dkimSelectors} onChange={(e) => setDkimSelectors(e.target.value)} placeholder="selector1, google, k1"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">SMTP ports</label>
                    <input type="text" value={smtpPorts} onChange={(e) => setSmtpPorts(e.target.value)} placeholder="25,465,587"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">Mail subdomains to probe</label>
                    <input type="text" value={mailSubdomains} onChange={(e) => setMailSubdomains(e.target.value)} placeholder="mail,autodiscover,webmail"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">Min DKIM bits</label>
                      <input type="number" min="1024" max="4096" step="1024" value={minDkimBits} onChange={(e) => setMinDkimBits(e.target.value)}
                        className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">SPF lookup limit</label>
                      <input type="number" min="1" max="20" step="1" value={spfLookupLimit} onChange={(e) => setSpfLookupLimit(e.target.value)}
                        className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">Per-probe timeout (ms)</label>
                    <input type="number" min="1000" max="20000" step="500" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-white/25 mt-3">Last completed: {lastRun}</p>}
      </div>

      {!clientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          Select an in-scope client and target domain to run the email-trust posture scan.
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
        emptyReadyTitle="Run a posture scan to assess SPF, DKIM, DMARC, BIMI, MTA-STS, DNSSEC, DANE & SMTP TLS."
        emptyReadyBody="No exposures returned — email-trust posture appears strong."
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
