import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

// Command Center GUI for the `bgp_dns_hijacking` engine (DNS & BGP Hijack-Resistance).
// Every control maps 1:1 to a real engine parameter read from the scan body via ArsenalConfig.
const ENGINE = 'bgp_dns_hijacking'
const ACCENT = '#22d3ee'

// Probe toggles — exact keys consumed by the engine's load_config().
const TOGGLES = [
  { key: 'check_resolver_consensus', label: 'Multi-resolver consensus', hint: 'Cross-resolver answer divergence (poisoning / split-horizon hijack)', defaultVal: true },
  { key: 'check_dnssec', label: 'DNSSEC chain validation', hint: 'AD flag + DS/DNSKEY presence + broken-chain detection', defaultVal: true },
  { key: 'check_rpki', label: 'RPKI ROA validation', hint: 'Validate (prefix, origin-AS) against RPKI ROAs', defaultVal: true },
  { key: 'check_bgp', label: 'BGP origin / MOAS', hint: 'Multiple-Origin-AS + unexpected-origin detection', defaultVal: true },
  { key: 'check_caa', label: 'CAA issuance control', hint: 'Certificate-authority authorization records', defaultVal: true },
  { key: 'check_ns', label: 'Name-server diversity', hint: 'Authoritative NS origin-AS spread', defaultVal: true },
  { key: 'check_takeover', label: 'Subdomain takeover (CNAME)', hint: 'Dangling CNAMEs to unclaimed providers', defaultVal: true },
  { key: 'check_aaaa', label: 'IPv6 (AAAA) consensus', hint: 'Also cross-check AAAA records', defaultVal: false },
  { key: 'check_tls_identity', label: 'TLS identity binding', hint: 'Live cert on :443 must cover the scanned name', defaultVal: true },
  { key: 'check_bogon', label: 'Bogon / martian IP detection', hint: 'RFC1918, loopback, TEST-NET in public DNS answers', defaultVal: true },
  { key: 'check_ttl', label: 'Low-TTL / fast-flux signal', hint: 'A-record TTL below threshold (pre-hijack pattern)', defaultVal: true },
  { key: 'check_routing_history', label: 'BGP routing-history drift', hint: 'Origin-AS churn on covering prefix (RIPEstat)', defaultVal: true },
  { key: 'check_dane', label: 'DANE / TLSA', hint: 'Certificate association records in DNS', defaultVal: true },
  { key: 'check_ct', label: 'Certificate Transparency inventory', hint: 'crt.sh passive cert count + recent issuers', defaultVal: true },
  { key: 'check_auth_recursive', label: 'Authoritative vs recursive', hint: 'Direct NS query (UDP/53) vs DoH — detects cache poisoning', defaultVal: true },
  { key: 'check_rdap', label: 'RDAP registrar lock', hint: 'clientTransferProhibited — blocks domain theft hijack', defaultVal: true },
  { key: 'check_irr', label: 'IRR vs live BGP', hint: 'Route registry must match observed origin AS', defaultVal: true },
  { key: 'check_more_specific', label: 'More-specific BGP hijack', hint: 'Foreign shorter prefixes under your aggregate', defaultVal: true },
  { key: 'check_dual_stack', label: 'IPv4/IPv6 origin binding', hint: 'A and AAAA must share origin AS', defaultVal: true },
  { key: 'check_soa', label: 'SOA MNAME integrity', hint: 'SOA primary must appear in NS set', defaultVal: true },
  { key: 'check_baseline_delta', label: 'Baseline regression delta', hint: 'Compare A IPs / origin AS / score vs prior scan (DB)', defaultVal: true },
  { key: 'check_caa_ct_cross', label: 'CAA ⟷ CT cross-check', hint: 'Flag CT issuers not allowed by CAA', defaultVal: true },
  { key: 'check_rpki_maxlength', label: 'RPKI maxLength slack', hint: 'Loose ROA maxLength = more-specific hijack window', defaultVal: true },
  { key: 'check_hsts', label: 'HSTS presence', hint: 'Strict-Transport-Security on HTTPS', defaultVal: true },
  { key: 'check_http_redirect', label: 'HTTP redirect binding', hint: 'http:// must not redirect off-domain', defaultVal: true },
  { key: 'check_mx_origin', label: 'MX vs web origin AS', hint: 'Mail exchanger must align with web infrastructure', defaultVal: true },
  { key: 'check_glue', label: 'In-bailiwick NS glue', hint: 'Child NS names must have glue A records', defaultVal: true },
  { key: 'check_bgp_visibility', label: 'BGP global visibility', hint: 'RIPEstat routing-status visibility %', defaultVal: true },
  { key: 'check_geo', label: 'Geo country binding', hint: 'Requires expected_countries (ISO-2) in params', defaultVal: false },
  { key: 'check_dnssec_ad_divergence', label: 'DNSSEC AD-flag divergence', hint: 'Validating resolvers must agree on AD bit', defaultVal: true },
  { key: 'check_fcrdns', label: 'FCrDNS (forward-confirmed PTR)', hint: 'PTR must forward-resolve back to A record', defaultVal: true },
  { key: 'check_expected_ips', label: 'Expected A IP allow-list', hint: 'Requires expected_a_ips — foreign A = hijack', defaultVal: false },
  { key: 'check_cname_chain', label: 'CNAME chain audit', hint: 'Follow chain; flag off-zone terminators', defaultVal: true },
  { key: 'check_spf_apex', label: 'SPF at apex', hint: 'Email-path DNS integrity (v=spf1 TXT)', defaultVal: true },
  { key: 'check_wildcard', label: 'Wildcard DNS probe', hint: 'Random subdomain must not catch-all to foreign IPs', defaultVal: true },
  { key: 'check_ns_lame', label: 'Lame delegation', hint: 'Every NS must answer authoritatively', defaultVal: true },
  { key: 'check_cds_cdnskey', label: 'CDS/CDNSKEY automation', hint: 'DNSSEC key rollover automation readiness', defaultVal: true },
  { key: 'check_orphan_ds', label: 'Orphan DS detection', hint: 'DS without zone DNSKEY — broken chain', defaultVal: true },
  { key: 'check_resolver_timing', label: 'Resolver timing anomaly', hint: 'One resolver path disproportionately slow', defaultVal: true },
  { key: 'autonomous_mode', label: 'Autonomous discovery (v7)', hint: 'Adapt probes to live zone surface — not a static checklist', defaultVal: true },
  { key: 'check_ct_discovery', label: 'CT-driven host discovery', hint: 'Pull hostnames from crt.sh and probe dynamically', defaultVal: true },
  { key: 'check_delegation_walk', label: 'Delegation chain walk', hint: 'Walk parent zones and validate delegation', defaultVal: true },
  { key: 'check_udp_doh_cross', label: 'UDP/53 vs DoH cross-check', hint: 'Compare Google UDP recursive with DoH consensus', defaultVal: true },
  { key: 'check_dmarc', label: 'DMARC at _dmarc', hint: 'Email-path integrity when MX/SPF exist', defaultVal: true },
  { key: 'check_parent_ns', label: 'Parent/child NS consistency', hint: 'Child NS vs parent zone delegation', defaultVal: true },
  { key: 'check_soa_serial', label: 'SOA serial auth consensus (v8)', hint: 'Each auth NS must publish the same SOA serial', defaultVal: true },
  { key: 'check_discovered_tls', label: 'Discovered-host TLS spot-check (v8)', hint: 'Live TLS on CT/DNS-discovered hostnames', defaultVal: true },
  { key: 'discovered_tls_limit', label: 'Discovered TLS sample size', hint: 'Max hostnames to spot-check per scan', defaultVal: 5, type: 'number' },
  { key: 'force_all_probes', label: 'Force all probes (disable skip)', hint: 'Run every probe even when zone surface does not require it', defaultVal: false },
  { key: 'use_static_subdomain_wordlist', label: 'Static subdomain wordlist', hint: 'Off by default in autonomous mode — engine discovers hosts from live DNS/CT', defaultVal: false },
]

const PLANE_STYLE = {
  healthy: { bd: 'border-emerald-500/40', bg: 'bg-emerald-500/10', text: 'text-emerald-300' },
  degraded: { bd: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-300' },
  compromised: { bd: 'border-rose-500/40', bg: 'bg-rose-500/10', text: 'text-rose-300' },
  unknown: { bd: 'border-white/10', bg: 'bg-white/5', text: 'text-white/40' },
}

const POSTURE_DIMS = [
  { key: 'baseline_stable', label: 'Baseline stable', positive: true },
  { key: 'caa_ct_aligned', label: 'CAA ⟷ CT aligned', positive: true },
  { key: 'hsts_present', label: 'HSTS present', positive: true },
  { key: 'redirect_healthy', label: 'HTTP redirect OK', positive: true },
  { key: 'mx_origin_match', label: 'MX origin match', positive: true },
  { key: 'glue_consistent', label: 'NS glue OK', positive: true },
  { key: 'bgp_visible', label: 'BGP visible', positive: true },
  { key: 'geo_match', label: 'Geo match', positive: true },
  { key: 'rpki_maxlength_tight', label: 'RPKI maxLength tight', positive: true },
  { key: 'auth_recursive_match', label: 'Auth = recursive', positive: true },
  { key: 'rdap_transfer_locked', label: 'RDAP transfer lock', positive: true },
  { key: 'irr_matches_bgp', label: 'IRR matches BGP', positive: true },
  { key: 'more_specific_clean', label: 'No foreign more-specifics', positive: true },
  { key: 'dual_stack_origin_match', label: 'Dual-stack origin match', positive: true },
  { key: 'soa_mname_in_ns', label: 'SOA MNAME in NS', positive: true },
  { key: 'dnssec_validated', label: 'DNSSEC validated', positive: true },
  { key: 'dnskey_strong', label: 'Strong DNSKEY algorithms', positive: true },
  { key: 'rpki_valid', label: 'RPKI valid', positive: true },
  { key: 'resolver_consensus', label: 'Resolver consensus', positive: true },
  { key: 'tls_identity_match', label: 'TLS identity match', positive: true },
  { key: 'bogon_free', label: 'No bogon IPs', positive: true },
  { key: 'ttl_healthy', label: 'TTL healthy', positive: true },
  { key: 'bgp_origin_stable', label: 'BGP origin stable', positive: true },
  { key: 'dane_present', label: 'DANE/TLSA present', positive: true },
  { key: 'caa_present', label: 'CAA present', positive: true },
  { key: 'ns_diverse', label: 'NS diversity', positive: true },
  { key: 'dnssec_broken', label: 'DNSSEC broken', positive: false },
  { key: 'rpki_invalid', label: 'RPKI invalid', positive: false },
  { key: 'moas', label: 'Multi-origin AS (MOAS)', positive: false },
  { key: 'unexpected_origin', label: 'Unexpected origin AS', positive: false },
  { key: 'expected_ips_match', label: 'Expected IPs match', positive: true },
  { key: 'fcrdns_valid', label: 'FCrDNS valid', positive: true },
  { key: 'aaaa_consensus', label: 'AAAA consensus', positive: true },
  { key: 'ns_lame_free', label: 'No lame NS', positive: true },
  { key: 'wildcard_clean', label: 'Wildcard clean', positive: true },
  { key: 'dnssec_ad_consensus', label: 'DNSSEC AD consensus', positive: true },
  { key: 'cname_healthy', label: 'CNAME chain OK', positive: true },
  { key: 'spf_present', label: 'SPF at apex', positive: true },
  { key: 'resolver_timing_healthy', label: 'Resolver timing OK', positive: true },
  { key: 'orphan_ds_clean', label: 'No orphan DS', positive: true },
  { key: 'delegation_chain_valid', label: 'Delegation chain OK', positive: true },
  { key: 'udp_doh_consistent', label: 'UDP/DoH match', positive: true },
  { key: 'dmarc_present', label: 'DMARC present', positive: true },
  { key: 'parent_ns_consistent', label: 'Parent NS OK', positive: true },
  { key: 'soa_serial_consistent', label: 'SOA serial consensus', positive: true },
  { key: 'discovered_tls_match', label: 'Discovered-host TLS OK', positive: true },
  { key: 'takeover_clean', label: 'No dangling takeover', positive: true },
]

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-slate-300', bd: 'border-white/10', bg: 'bg-white/5', dot: '#94a3b8' },
}

function gradeFromScore(score) {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}
function gradeColor(grade) {
  return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c' }[grade] || '#fb7185'
}
function sevValue(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0
}
function csvToArray(s) {
  return String(s || '').split(/[,\s]+/).map((x) => x.trim()).filter(Boolean)
}
function isSummary(f) {
  return f && (f.type === 'dns_bgp_integrity_summary' || typeof f.hijack_resistance_score === 'number')
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-black/40 border border-white/5 p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-white/35 shrink-0">{k}</span>
              <span className="text-white/70 break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-white/5">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-white/30'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-white/60">{c.name}</span>
              <span className="text-white/30">—</span>
              <span className="text-white/45 break-all">{typeof c.detail === 'object' ? JSON.stringify(c.detail) : String(c.detail)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const controls = Array.isArray(f.controls) ? f.controls : []
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.mitre_attack && <span className="text-[10px] font-mono text-white/30">· {f.mitre_attack}</span>}
            {typeof f.confidence === 'number' && <span className="text-[10px] font-mono text-white/30">· conf {(f.confidence * 100).toFixed(0)}%</span>}
          </div>
          <div className="text-sm text-white/90 font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-white/30 text-xs mt-1">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-white/60 leading-relaxed mt-2">{f.description}</p>
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">Remediation</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {controls.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {controls.map((c) => (
                  <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/50 border border-white/10">{c}</span>
                ))}
              </div>
            )}
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = summary.hijack_resistance_score ?? summary.posture_score ?? 0
  const grade = gradeFromScore(score)
  const color = gradeColor(grade)
  const ev = summary.evidence || {}
  const planes = summary.threat_planes || ev.threat_planes || {}
  const roadmap = Array.isArray(summary.roadmap) ? summary.roadmap : (summary.roadmap ? [summary.roadmap] : [])
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
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
            <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{t('pages.dnsDomainPosture.hijack_resistance', 'Hijack-Resistance')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="text-[11px] font-mono text-white/40 mt-1">{summary.domain || summary.value || summary.target}</div>
            {summary.engine_version && <div className="text-[9px] font-mono text-cyan-500/50 mt-0.5">engine v{summary.engine_version}</div>}
          </div>
        </div>
        <div className="flex-1 space-y-4">
          {planes && typeof planes === 'object' && Object.keys(planes).length > 0 && (
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.threat_planes', 'Threat planes')}</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(planes).map(([name, data]) => {
                  const st = PLANE_STYLE[(data?.status || 'unknown').toLowerCase()] || PLANE_STYLE.unknown
                  return (
                    <div key={name} className={`rounded-lg border px-2 py-2 ${st.bd} ${st.bg}`}>
                      <div className="text-[9px] font-mono uppercase text-white/35">{name.replace('_', '/')}</div>
                      <div className={`text-[11px] font-mono font-semibold ${st.text}`}>{data?.status || 'unknown'}</div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
          <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.posture_dimensions', 'Posture dimensions')}</div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
            {POSTURE_DIMS.map((d) => {
              const raw = ev[d.key]
              if (raw === undefined || raw === null) return null
              const on = !!raw
              const ok = d.positive ? on : !on
              return (
                <div key={d.key} className={`flex items-center gap-1.5 rounded-lg border px-2 py-1 ${ok ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'}`}>
                  <span className={ok ? 'text-emerald-400' : 'text-rose-400'}>{ok ? '✓' : '✕'}</span>
                  <span className="text-[10px] font-mono text-white/60">{d.label}</span>
                </div>
              )
            })}
          </div>
          </div>
        </div>
      </div>
      {summary.critical_signal && (
        <div className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-sm text-rose-200 font-mono">
          ⚠ {t('pages.dnsDomainPosture.critical_signal', 'Critical hijack signal — multi-plane corroboration detected')}
        </div>
      )}
      {summary.incident_bundle && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.incident_bundle', 'SOC incident bundle')}</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] font-mono">
            {Array.isArray(summary.incident_bundle.mitre_techniques) && summary.incident_bundle.mitre_techniques.length > 0 && (
              <div>
                <span className="text-white/35">MITRE: </span>
                <span className="text-cyan-300/80">{summary.incident_bundle.mitre_techniques.join(', ')}</span>
              </div>
            )}
            {Array.isArray(summary.incident_bundle.priority_actions) && summary.incident_bundle.priority_actions.length > 0 && (
              <div>
                <span className="text-white/35">{t('pages.dnsDomainPosture.first_actions', 'First actions')}: </span>
                <span className="text-amber-200/80">{summary.incident_bundle.priority_actions.slice(0, 3).join(' → ')}</span>
              </div>
            )}
          </div>
        </div>
      )}
      {summary.discovery_graph && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.discovery_graph', 'Autonomous discovery graph')}</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
            {Array.isArray(summary.discovery_graph.signals) && summary.discovery_graph.signals.length > 0 && (
              <div><span className="text-white/35">Signals: </span><span className="text-emerald-300/80">{summary.discovery_graph.signals.join(', ')}</span></div>
            )}
            {Array.isArray(summary.discovery_graph.auto_enabled) && (
              <div><span className="text-white/35">Auto-enabled: </span><span className="text-cyan-300/70">{summary.discovery_graph.auto_enabled.length} probes</span></div>
            )}
            {typeof summary.discovery_graph.discovered_hosts_total === 'number' && summary.discovery_graph.discovered_hosts_total > 0 && (
              <div><span className="text-white/35">Discovered hosts: </span><span className="text-white/60">{summary.discovery_graph.discovered_hosts_total}</span></div>
            )}
            {Array.isArray(summary.discovery_graph.discovered_hosts_sample) && summary.discovery_graph.discovered_hosts_sample.length > 0 && (
              <div className="sm:col-span-2"><span className="text-white/35">Sample: </span><span className="text-white/50 break-all">{summary.discovery_graph.discovered_hosts_sample.slice(0, 6).join(', ')}</span></div>
            )}
            {summary.autonomous_mode != null && (
              <div><span className="text-white/35">Autonomous: </span><span className="text-white/60">{summary.autonomous_mode ? 'on' : 'off'}</span></div>
            )}
          </div>
        </div>
      )}
      {summary.coverage_audit && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.dnsDomainPosture.coverage_audit', 'Probe coverage audit (v8)')}</div>
            {summary.coverage_audit.coverage_complete != null && (
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${summary.coverage_audit.coverage_complete ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}`}>
                {summary.coverage_audit.coverage_complete ? t('pages.dnsDomainPosture.coverage_complete', 'Full coverage') : t('pages.dnsDomainPosture.coverage_partial', 'Partial')}
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono mb-3">
            {typeof summary.coverage_audit.enabled_count === 'number' && (
              <div><span className="text-white/35">{t('pages.dnsDomainPosture.coverage_enabled', 'Enabled')}: </span><span className="text-white/70">{summary.coverage_audit.enabled_count}</span></div>
            )}
            {typeof summary.coverage_audit.executed_count === 'number' && (
              <div><span className="text-white/35">{t('pages.dnsDomainPosture.coverage_executed', 'Executed')}: </span><span className="text-white/70">{summary.coverage_audit.executed_count}</span></div>
            )}
            {typeof summary.coverage_audit.passed_count === 'number' && (
              <div><span className="text-white/35">{t('pages.dnsDomainPosture.coverage_passed', 'Passed')}: </span><span className="text-emerald-300/80">{summary.coverage_audit.passed_count}</span></div>
            )}
            {typeof summary.coverage_audit.failed_count === 'number' && (
              <div><span className="text-white/35">{t('pages.dnsDomainPosture.coverage_failed', 'Failed')}: </span><span className="text-rose-300/80">{summary.coverage_audit.failed_count}</span></div>
            )}
          </div>
          {Array.isArray(summary.coverage_audit.probes) && summary.coverage_audit.probes.length > 0 && (
            <div className="max-h-40 overflow-y-auto rounded-lg border border-white/5 bg-black/20 p-2 space-y-0.5">
              {summary.coverage_audit.probes.filter((p) => p.enabled).map((p) => (
                <div key={p.id} className="flex items-center justify-between gap-2 text-[10px] font-mono">
                  <span className="text-white/50 truncate">{p.id}</span>
                  <span className={
                    p.status === 'pass' ? 'text-emerald-400' :
                    p.status === 'fail' ? 'text-rose-400' :
                    p.status === 'skipped' ? 'text-amber-400' : 'text-white/30'
                  }>{p.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {roadmap.length > 0 && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.hardening_roadmap', 'Hardening roadmap')}</div>
          <ol className="space-y-1">
            {roadmap.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-white/60">
                <span className="text-cyan-400">{i + 1}.</span>{r}
              </li>
            ))}
          </ol>
        </div>
      )}
    </motion.div>
  )
}

export default function DnsDomainPosture() {
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

  // Parameters (1:1 with the engine's load_config()).
  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [expectedAsns, setExpectedAsns] = useState('')
  const [subdomains, setSubdomains] = useState('')
  const [maxCtHosts, setMaxCtHosts] = useState(32)
  const [ripeBase, setRipeBase] = useState('https://stat.ripe.net')
  const [resolversText, setResolversText] = useState('')
  const [timeoutMs, setTimeoutMs] = useState(8000)
  const [concurrency, setConcurrency] = useState(16)
  const [lowTtlThreshold, setLowTtlThreshold] = useState(300)
  const [expectedCountries, setExpectedCountries] = useState('')
  const [expectedAips, setExpectedAips] = useState('')
  const [resolverTimingFactor, setResolverTimingFactor] = useState(3)

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
      max_ct_hosts: Number(maxCtHosts) || 32,
      ripe_base: ripeBase.trim() || 'https://stat.ripe.net',
      timeout_ms: Number(timeoutMs) || 8000,
      concurrency: Number(concurrency) || 16,
      low_ttl_threshold_secs: Number(lowTtlThreshold) || 300,
    }
    if (clientId) body.client_id = Number(clientId)
    const asns = csvToArray(expectedAsns)
    if (asns.length) body.expected_origin_asns = asns
    const countries = csvToArray(expectedCountries).map((c) => c.toUpperCase()).filter((c) => c.length === 2)
    if (countries.length) body.expected_countries = countries
    const aips = csvToArray(expectedAips)
    if (aips.length) body.expected_a_ips = aips
    if (toggles.check_expected_ips && aips.length === 0) body.check_expected_ips = false
    if (toggles.use_static_subdomain_wordlist) {
      const subs = csvToArray(subdomains)
      if (subs.length) body.subdomains = subs
    }
    body.resolver_timing_factor = Number(resolverTimingFactor) || 3
    const resolvers = resolversText.split('\n').map((x) => x.trim()).filter(Boolean)
    if (resolvers.length) body.resolvers = resolvers
    return body
  }, [target, toggles, subdomains, maxCtHosts, ripeBase, timeoutMs, concurrency, lowTtlThreshold, expectedCountries, expectedAips, resolverTimingFactor, clientId, expectedAsns, resolversText])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.dnsDomainPosture.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.dnsDomainPosture.target_required', 'A target domain is required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.dnsDomainPosture.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.dnsDomainPosture.queued', 'Posture scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.dnsDomainPosture.scan_failed', 'Scan failed'))
    }
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.dnsDomainPosture.title', 'DNS & BGP Hijack-Resistance')}
      badge={t('pages.dnsDomainPosture.badge', 'DNS / DNSSEC / BGP / RPKI')}
      badgeColor={ACCENT}
      subtitle={t('pages.dnsDomainPosture.subtitle', 'World-class hijack resistance — authoritative NS direct query, recursive consensus, DNSSEC, RPKI/BGP/IRR, RDAP lock, TLS bind, dual-stack & compound detection. Live, read-only.')}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.dnsDomainPosture.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40 min-w-[180px]">
              <option value="">{t('pages.dnsDomainPosture.select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.dnsDomainPosture.target_domain', 'Target domain')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="example.com"
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #22d3ee' : 'none' }} />
            <span className="text-[10px] font-mono text-white/40 uppercase">{status}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? t('pages.dnsDomainPosture.scanning', '⟳ Scanning…') : t('pages.dnsDomainPosture.run_scan', '▶ Run Posture Scan')}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-all">
            {showParams ? t('pages.dnsDomainPosture.hide_params', '▾ Parameters') : t('pages.dnsDomainPosture.show_params', '▸ Parameters')}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-white/5 grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.dnsDomainPosture.probe_categories', 'Probe categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-white/70 cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-cyan-500" />
                        {tg.label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.expected_asns', 'Expected origin ASNs')}</label>
                    <input type="text" value={expectedAsns} onChange={(e) => setExpectedAsns(e.target.value)} placeholder="AS13335, AS15169"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.expected_a_ips', 'Expected A IPs (allow-list)')}</label>
                    <input type="text" value={expectedAips} onChange={(e) => setExpectedAips(e.target.value)} placeholder="203.0.113.10, 203.0.113.11"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.expected_countries', 'Expected countries (ISO-2, geo check)')}</label>
                    <input type="text" value={expectedCountries} onChange={(e) => setExpectedCountries(e.target.value)} placeholder="US, IL"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.subdomains', 'Static subdomain wordlist (optional)')}</label>
                    <input type="text" value={subdomains} onChange={(e) => setSubdomains(e.target.value)} placeholder="www, api — only when static wordlist enabled"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.max_ct_hosts', 'Max CT hosts to discover')}</label>
                    <input type="number" min="8" max="128" step="8" value={maxCtHosts} onChange={(e) => setMaxCtHosts(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.ripe_base', 'RIPEstat base URL')}</label>
                    <input type="text" value={ripeBase} onChange={(e) => setRipeBase(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.timeout_ms', 'Timeout (ms)')}</label>
                      <input type="number" min="1000" max="30000" step="500" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                        className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.concurrency', 'Concurrency')}</label>
                      <input type="number" min="1" max="16" step="1" value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                        className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.low_ttl_threshold', 'Low-TTL threshold (s)')}</label>
                      <input type="number" min="30" max="86400" step="30" value={lowTtlThreshold} onChange={(e) => setLowTtlThreshold(e.target.value)}
                        className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40" />
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.dnsDomainPosture.resolvers', 'Custom resolvers (name=DoH-URL per line)')}</label>
                    <textarea rows={3} value={resolversText} onChange={(e) => setResolversText(e.target.value)} placeholder={'cloudflare=https://cloudflare-dns.com/dns-query\ngoogle=https://dns.google/resolve'}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] text-white/80 font-mono focus:outline-none focus:border-cyan-500/40 resize-y" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-white/25 mt-3">{t('pages.dnsDomainPosture.last_completed', 'Last completed: {{time}}', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.dnsDomainPosture.select_client_warning', 'Select an in-scope client and target domain to run the posture scan.')}
        </div>
      )}

      <Scorecard summary={summary} t={t} />

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
        emptyReadyTitle={t('pages.dnsDomainPosture.run_to_populate', 'Run a posture scan to assess DNS resolution & BGP routing integrity.')}
        emptyReadyBody={t('pages.dnsDomainPosture.no_findings', 'No exposures returned — hijack-resistance posture appears strong.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
