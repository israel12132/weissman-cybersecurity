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
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import DataTable from '../components/ui/DataTable'
import { createColumnHelper } from '@tanstack/react-table'
import Button from '../components/ui/Button'

const columnHelper = createColumnHelper()

// Command Center GUI for the `cache_poisoning` engine (Web Cache Poisoning & Deception Posture).
// Every control maps 1:1 to a real engine parameter read from the scan body via ArsenalConfig.
const ENGINE = 'cache_poisoning'
const ACCENT = '#fb7185'

const TOGGLES = [
  { key: 'check_fingerprint', label: 'Cache / CDN fingerprint', hint: 'Detect shared cache layer + vendor and prove cacheability', defaultVal: true },
  { key: 'check_unkeyed', label: 'Unkeyed-input poisoning', hint: 'Reflect a canary through unkeyed headers + confirm cached', defaultVal: true },
  { key: 'check_query_unkeyed', label: 'Query-string poisoning', hint: 'Detect unkeyed query params reflected + cache-confirmed', defaultVal: true },
  { key: 'check_cookie_cache', label: 'Cookie-keyed caching', hint: 'Cookie-variant responses cached without Vary: Cookie', defaultVal: true },
  { key: 'check_hardening', label: 'Cache hardening (Vary / CC)', hint: 'Dynamic pages without no-store; Accept-Language without Vary', defaultVal: true },
  { key: 'check_fat_get', label: 'Fat GET poisoning', hint: 'GET with body — cache keys URL only (Normal+ intensity)', defaultVal: true },
  { key: 'check_method_confusion', label: 'GET/HEAD confusion', hint: 'Method-unkeyed cache — HEAD oracle after poison GET (Normal+)', defaultVal: true },
  { key: 'check_method_override', label: 'Method-override poisoning', hint: 'X-HTTP-Method-Override + GET body reflected & cached (Normal+)', defaultVal: true },
  { key: 'check_range_poisoning', label: 'Range-request poisoning', hint: '206 partial cached & served to full GET (Normal+)', defaultVal: true },
  { key: 'check_encoding_vary', label: 'Accept-Encoding fracture', hint: 'gzip vs identity without Vary: Accept-Encoding (Normal+)', defaultVal: true },
  { key: 'check_h2_schism', label: 'HTTP/2 cache schism', hint: 'HTTP/1.1 vs HTTP/2 body divergence on same URL (Normal+)', defaultVal: true },
  { key: 'check_authorization_cache', label: 'Authorization session bleed', hint: 'Bearer token changes response without Vary: Authorization (Normal+)', defaultVal: true },
  { key: 'check_redirect_poisoning', label: 'Redirect cache poisoning', hint: 'Poisoned Location on 3xx cached without header (Normal+)', defaultVal: true },
  { key: 'check_cdn_schism', label: 'CDN vs origin Cache-Control schism', hint: 'CDN-Cache-Control overrides origin no-store/private', defaultVal: true },
  { key: 'check_user_agent_vary', label: 'User-Agent fracture', hint: 'Mobile vs desktop without Vary: User-Agent (Normal+)', defaultVal: true },
  { key: 'check_tracking_oracle', label: 'Tracking-param oracle', hint: 'utm/fbclid/gclid stripped from CDN cache key (Normal+)', defaultVal: true },
  { key: 'check_vary_incomplete', label: 'Incomplete Vary header', hint: 'Multi-dimension variance missing from Vary (Normal+)', defaultVal: true },
  { key: 'check_stale_revalidate', label: 'Stale-while-revalidate risk', hint: 'Dynamic pages with stale extensions at CDN', defaultVal: true },
  { key: 'check_accept_vary', label: 'Accept negotiation fracture', hint: 'HTML vs JSON Accept without Vary (Normal+)', defaultVal: true },
  { key: 'check_post_cache', label: 'POST→GET cache bleed', hint: 'POST body poison served to GET (Aggressive)', defaultVal: true },
  { key: 'check_immutable_dynamic', label: 'Immutable on dynamic HTML', hint: 'Cache-Control immutable on session pages', defaultVal: true },
  { key: 'check_etag_injection', label: 'ETag / validator injection', hint: 'Canary in ETag from X-Forwarded-Host (Normal+)', defaultVal: true },
  { key: 'check_case_header', label: 'Case-fold header oracle', hint: 'Lowercase x-forwarded-host poisons cache (Normal+)', defaultVal: true },
  { key: 'check_path_discover', label: 'Auto path discovery', hint: 'Harvest same-origin hrefs from HTML for multi-path scan', defaultVal: true },
  { key: 'check_normalization', label: 'Normalization oracle', hint: 'Path/query normalization collapsing cache keys (Aggressive)', defaultVal: true },
  { key: 'check_cache_key_oracle', label: 'Cache-key oracle', hint: 'Query dimensions excluded from CDN cache key (Aggressive)', defaultVal: true },
  { key: 'check_query_order', label: 'Query-order oracle', hint: 'Param order normalization shares cache slot (Aggressive)', defaultVal: true },
  { key: 'check_sec_fetch', label: 'Sec-Fetch fracture', hint: 'document vs image without Vary: Sec-Fetch-* (Normal+)', defaultVal: true },
  { key: 'check_save_data', label: 'Save-Data fracture', hint: 'Save-Data:on variant without Vary (Normal+)', defaultVal: true },
  { key: 'check_options_cache', label: 'OPTIONS cache oracle', hint: 'OPTIONS byte-identical to GET and cacheable (Normal+)', defaultVal: true },
  { key: 'check_pragma_oracle', label: 'Pragma no-cache ignored', hint: 'CDN HIT despite client Pragma/Cache-Control no-cache', defaultVal: true },
  { key: 'check_forwarded_rfc7239', label: 'RFC7239 Forwarded poisoning', hint: 'Structured host=…;proto=https canary + cache confirm (Normal+)', defaultVal: true },
  { key: 'check_host_header', label: 'Host header override', hint: 'Host differs from URL authority — reflection + cache confirm (Normal+)', defaultVal: true },
  { key: 'check_edge_no_store', label: 'Edge no-store bypass', hint: 'Origin no-store/private but CDN still HITs', defaultVal: true },
  { key: 'check_vary_star', label: 'Vary: * misconfiguration', hint: 'Wildcard Vary with publicly cacheable shared response', defaultVal: true },
  { key: 'check_link_header', label: 'Link header poisoning', hint: 'rel=canonical Link injection reflected + cache confirm (Normal+)', defaultVal: true },
  { key: 'check_duplicate_query', label: 'Duplicate query-param oracle', hint: 'Repeated param names share cache slot (Aggressive)', defaultVal: true },
  { key: 'check_accept_lang_order', label: 'Accept-Language order fracture', hint: 'Lang order changes body without Vary (Normal+)', defaultVal: true },
  { key: 'check_if_none_match', label: 'If-None-Match / 304 amplifier', hint: 'Poisoned ETag returns 304 from shared cache (Normal+)', defaultVal: true },
  { key: 'check_if_modified_since', label: 'If-Modified-Since / 304 amplifier', hint: 'Poisoned Last-Modified returns 304 from shared cache (Normal+)', defaultVal: true },
  { key: 'check_duplicate_header', label: 'Duplicate X-Forwarded-Host oracle', hint: 'Twin header values — CDN keys first, origin reflects second (Normal+)', defaultVal: true },
  { key: 'check_s_maxage_schism', label: 's-maxage vs max-age schism', hint: 'Browser-private but CDN-public Cache-Control line', defaultVal: true },
  { key: 'check_brotli_vary', label: 'Brotli encoding fracture', hint: 'br vs identity without Vary: Accept-Encoding (Normal+)', defaultVal: true },
  { key: 'check_sec_ch_ua', label: 'Sec-CH-UA fracture', hint: 'Client hints change body without Vary (Normal+)', defaultVal: true },
  { key: 'check_forwarded_prefix', label: 'X-Forwarded-Prefix poisoning', hint: 'Path prefix injection reflected + cache confirm (Normal+)', defaultVal: true },
  { key: 'check_set_cookie_cache_bleed', label: 'Set-Cookie cache bleed', hint: 'Set-Cookie response served on CDN HIT', defaultVal: true },
  { key: 'check_stale_if_error', label: 'Stale-if-error risk', hint: 'Dynamic pages with stale-if-error at CDN prolong poison', defaultVal: true },
  { key: 'check_sec_ch_viewport', label: 'Sec-CH-Viewport fracture', hint: 'Viewport hint changes body without Vary (Normal+)', defaultVal: true },
  { key: 'check_trailing_dot_host', label: 'Trailing-dot Host', hint: 'Host with trailing dot reflected + cache confirm (Normal+)', defaultVal: true },
  { key: 'check_protocol_relative_redirect', label: 'Protocol-relative redirect', hint: 'Location //host on cacheable 3xx (Normal+)', defaultVal: true },
  { key: 'check_deception', label: 'Web cache deception', hint: 'Static-suffix path confusion caching dynamic pages', defaultVal: true },
]

const POSTURE_DIMS = [
  { key: 'unkeyed_inputs', label: 'Unkeyed inputs', color: '#fb7185' },
  { key: 'method_keying', label: 'Method keying', color: '#e879f9' },
  { key: 'normalization', label: 'Normalization', color: '#c084fc' },
  { key: 'session_isolation', label: 'Session isolation', color: '#fbbf24' },
  { key: 'deception_resistance', label: 'Deception resistance', color: '#fb923c' },
  { key: 'cache_key_integrity', label: 'Cache-key integrity', color: '#38bdf8' },
  { key: 'protocol_isolation', label: 'Protocol isolation', color: '#a78bfa' },
  { key: 'auth_isolation', label: 'Auth isolation', color: '#f472b6' },
  { key: 'client_variant_isolation', label: 'Client variants', color: '#34d399' },
]

const CATEGORY_META = {
  cache_fingerprint: { label: 'Cache / CDN Fingerprint', icon: '🌐', color: '#38bdf8', order: 1 },
  cache_poisoning: { label: 'Cache Poisoning', icon: '☠', color: '#fb7185', order: 2 },
  cache_method: { label: 'Method / Range Primitives', icon: '⚡', color: '#e879f9', order: 3 },
  cache_protocol: { label: 'Protocol Schism', icon: '🔌', color: '#a78bfa', order: 4 },
  cache_key_oracle: { label: 'Cache-Key Oracle', icon: '🔑', color: '#22d3ee', order: 5 },
  cache_normalization: { label: 'Normalization Fracture', icon: '🔀', color: '#c084fc', order: 6 },
  cache_deception: { label: 'Web Cache Deception', icon: '🎭', color: '#fb923c', order: 7 },
  cookie_cache: { label: 'Cookie-keyed Caching', icon: '🍪', color: '#fbbf24', order: 8 },
  auth_cache: { label: 'Authorization Bleed', icon: '🔐', color: '#f472b6', order: 9 },
  redirect_cache: { label: 'Redirect Poisoning', icon: '↪', color: '#e879f9', order: 10 },
  cache_hardening: { label: 'Cache Hardening', icon: '🛡', color: '#a78bfa', order: 11 },
  other: { label: 'Other', icon: '•', color: '#94a3b8', order: 99 },
}

const SEV_MATRIX_COLORS = {
  critical: '#fb7185',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  info: '#64748b',
}

const SEV_MATRIX_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function RiskMatrix({ matrix, t }) {
  const data = useMemo(() => {
    if (!matrix || typeof matrix !== 'object') return []
    return Object.keys(matrix).sort().map((cat) => {
      const row = matrix[cat] || {}
      const meta = CATEGORY_META[cat] || CATEGORY_META.other
      return {
        cat,
        icon: meta.icon,
        label: meta.label,
        critical: Number(row.critical || 0),
        high: Number(row.high || 0),
        medium: Number(row.medium || 0),
        low: Number(row.low || 0),
        info: Number(row.info || 0),
      }
    })
  }, [matrix])

  const columns = useMemo(() => [
    columnHelper.accessor((r) => r.label, {
      id: 'category',
      header: t('pages.webCachePosture.category', 'Category'),
      cell: (ctx) => (
        <span className="text-[var(--text-tertiary)] whitespace-nowrap">{ctx.row.original.icon} {ctx.row.original.label}</span>
      ),
    }),
    ...SEV_MATRIX_ORDER.map((s) => columnHelper.accessor((r) => r[s], {
      id: s,
      header: s.slice(0, 4),
      cell: (ctx) => {
        const n = ctx.row.original[s]
        return n > 0 ? (
          <span className="inline-block min-w-[1.25rem] px-1 rounded font-bold text-center" style={{ backgroundColor: `${SEV_MATRIX_COLORS[s]}22`, color: SEV_MATRIX_COLORS[s] }}>{n}</span>
        ) : (
          <span className="text-[var(--text-disabled)]">·</span>
        )
      },
    })),
  ], [t])

  if (data.length === 0) return null

  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.webCachePosture.risk_matrix', 'Risk matrix (category × severity)')}</div>
      <DataTable
        columns={columns}
        data={data}
        animateRows={false}
        getRowId={(item) => item.cat}
      />
    </div>
  )
}

function CdnPlaybook({ playbook, t }) {
  if (!playbook || !Array.isArray(playbook.steps) || playbook.steps.length === 0) return null
  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 mb-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400/80">{t('pages.webCachePosture.cdn_playbook', 'CDN hardening playbook')}</div>
        {playbook.vendor && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-cyan-500/30 text-cyan-300/80 bg-cyan-500/5">{playbook.vendor}</span>
        )}
      </div>
      <ol className="space-y-1.5">
        {playbook.steps.map((step, i) => (
          <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">
            <span className="text-cyan-400 shrink-0">{i + 1}.</span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function TopPrimitives({ items, t }) {
  if (!Array.isArray(items) || items.length === 0) return null
  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400/80 mb-2">{t('pages.webCachePosture.top_primitives', 'Top primitives (triage)')}</div>
      <ol className="space-y-1.5">
        {items.map((p, i) => (
          <li key={i} className="rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono text-rose-300">{i + 1}.</span>
              <span className="text-[10px] font-mono uppercase text-rose-300/80">{p.severity}</span>
              {p.exposure && <span className="text-[10px] font-mono text-[var(--text-muted)]">· {p.exposure}</span>}
              {typeof p.confidence === 'number' && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">· {(p.confidence * 100).toFixed(0)}%</span>
              )}
            </div>
            <div className="text-xs text-[var(--text-primary)] font-medium mt-0.5">{p.title}</div>
            {p.url && <div className="text-[10px] font-mono text-[var(--text-muted)] mt-0.5 truncate">{p.url}</div>}
          </li>
        ))}
      </ol>
    </div>
  )
}

function ComplianceMap({ map, t }) {
  if (!map || typeof map !== 'object') return null
  const cwe = Array.isArray(map.cwe) ? map.cwe : []
  const owasp = Array.isArray(map.owasp) ? map.owasp : []
  const mitre = Array.isArray(map.mitre_attack) ? map.mitre_attack : []
  if (cwe.length === 0 && owasp.length === 0 && mitre.length === 0) return null
  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.webCachePosture.compliance_map', 'Compliance mapping')}</div>
      <div className="flex flex-wrap gap-3 text-[10px] font-mono">
        {mitre.map((m) => <span key={m} className="px-2 py-0.5 rounded bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)]">{m}</span>)}
        {cwe.map((c) => <span key={c} className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/25 text-amber-200/80">{c}</span>)}
        {owasp.map((o) => <span key={o} className="px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/25 text-sky-200/80">{o}</span>)}
      </div>
    </div>
  )
}

function CoverageManifest({ manifest, t }) {
  if (!manifest || typeof manifest !== 'object') return null
  const complete = manifest.sealed_complete === true || manifest.coverage_complete === true || manifest.competitive_parity === 'world_class_complete'
  const dims = Array.isArray(manifest.competitive_dimensions) ? manifest.competitive_dimensions : []
  const enabled = manifest.probes_enabled ?? 0
  const total = manifest.probe_categories_total ?? 0
  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400/80">{t('pages.webCachePosture.coverage_manifest', 'Competitive coverage')}</div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${complete ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-amber-500/40 text-amber-300 bg-amber-500/10'}`}>
          {enabled}/{total} {t('pages.webCachePosture.probes', 'probes')}
        </span>
        {manifest.sealed_complete && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/50 text-emerald-200 bg-emerald-500/15">
            {t('pages.webCachePosture.sealed', 'SEALED')}
          </span>
        )}
        {manifest.engine_version && <span className="text-[10px] font-mono text-[var(--text-disabled)]">{manifest.engine_version}</span>}
      </div>
      {dims.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {dims.map((d) => (
            <span key={d} className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/5 border border-emerald-500/20 text-emerald-200/70">{d.replace(/_/g, ' ')}</span>
          ))}
        </div>
      )}
    </div>
  )
}

function DefenseControls({ controls, t }) {
  if (!controls || !Array.isArray(controls.controls_required) || controls.controls_required.length === 0) return null
  return (
    <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 mb-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-violet-400/80">{t('pages.webCachePosture.defense_controls', 'Required defense controls')}</div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-violet-500/30 text-violet-300/80 bg-violet-500/5">{controls.control_count ?? controls.controls_required.length}</span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {controls.controls_required.map((c) => (
          <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/25 text-violet-200/80">{c.replace(/_/g, ' ')}</span>
        ))}
      </div>
    </div>
  )
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

function gradeColor(g) { return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c' }[g] || '#fb7185' }
function csvToArray(s) { return String(s || '').split(/[,\s]+/).map((x) => x.trim()).filter(Boolean) }
function isSummary(f) { return f && (f.category === 'posture_summary' || f.summary === true || typeof f.posture_score === 'number') }

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-[var(--text-muted)] shrink-0">{k}</span>
              <span className="text-[var(--text-secondary)] break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-[var(--border-subtle)]">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-[var(--text-tertiary)]">{c.name}</span>
              <span className="text-[var(--text-disabled)]">—</span>
              <span className="text-[var(--text-muted)] break-all">{typeof c.detail === 'object' ? JSON.stringify(c.detail) : String(c.detail)}</span>
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
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.exposure && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.exposure}</span>}
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
            {typeof f.confidence === 'number' && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· conf {(f.confidence * 100).toFixed(0)}%</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">Remediation</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {controls.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {controls.map((c) => (
                  <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border border-[var(--border-default)]">{c}</span>
                ))}
              </div>
            )}
            {f.evidence?.poc_curl && (
              <div className="mt-2 rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-cyan-400/70 mb-1">PoC (curl)</div>
                <p className="text-[10px] font-mono text-cyan-100/80 break-all leading-relaxed">{f.reproduction_hint || f.evidence.poc_curl}</p>
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
  const score = summary.posture_score ?? summary.evidence?.posture_score ?? 100
  const grade = summary.grade ?? summary.evidence?.grade ?? 'A'
  const color = gradeColor(grade)
  const ev = summary.evidence || {}
  const bd = ev.severity_breakdown || summary.evidence?.severity_breakdown || {}
  const cats = summary.weak_categories || ev.weak_categories || []
  const cached = summary.shared_cache_detected ?? ev.shared_cache_detected
  const dims = summary.posture_dimensions || ev.posture_dimensions || {}
  const roadmap = Array.isArray(summary.hardening_roadmap) ? summary.hardening_roadmap : []
  const attackChains = Array.isArray(summary.attack_chains) ? summary.attack_chains : []
  const probeManifest = summary.probe_manifest || ev.probe_manifest || null
  const exploitIdx = summary.exploitability_index ?? ev.exploitability_index
  const confirmedPrimitives = summary.confirmed_primitives ?? ev.confirmed_primitives
  const beyondScore = summary.beyond_score ?? ev.beyond_score
  const scanTelemetry = summary.scan_telemetry || ev.scan_telemetry || null
  const riskMatrix = summary.risk_matrix || ev.risk_matrix || null
  const cdnPlaybook = summary.cdn_playbook || ev.cdn_playbook || null
  const defenseControls = summary.defense_controls || ev.defense_controls || null
  const topPrimitives = summary.top_primitives || ev.top_primitives || null
  const complianceMap = summary.compliance_map || ev.compliance_map || null
  const poisonWindow = summary.poison_window_seconds ?? ev.poison_window_seconds
  const coverageManifest = summary.coverage_manifest || ev.coverage_manifest || null
  const competitiveParity = summary.competitive_parity_index ?? ev.competitive_parity_index
  const detectedVendor = summary.detected_cdn_vendor ?? ev.detected_cdn_vendor
  const sevCounts = [['critical', bd.critical || 0], ['high', bd.high || 0], ['medium', bd.medium || 0], ['low', bd.low || 0]]
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="flex items-center gap-5 shrink-0">
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
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.webCachePosture.cache_hardening', 'Cache Hardening')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${cached ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10' : 'border-[var(--border-default)] text-[var(--text-muted)]'}`}>
                {cached ? t('pages.webCachePosture.shared_cache_yes', 'Shared cache detected') : t('pages.webCachePosture.shared_cache_no', 'No shared cache observed')}
              </span>
              {typeof exploitIdx === 'number' && exploitIdx > 0 && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-rose-500/40 text-rose-300 bg-rose-500/10">
                  {t('pages.webCachePosture.exploitability', 'Exploitability {{n}}/100', { n: exploitIdx })}
                </span>
              )}
              {typeof beyondScore === 'number' && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-violet-500/40 text-violet-300 bg-violet-500/10">
                  {t('pages.webCachePosture.beyond_score', 'Beyond {{n}}/100', { n: beyondScore })}
                </span>
              )}
              {typeof confirmedPrimitives === 'number' && confirmedPrimitives > 0 && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-orange-500/40 text-orange-300 bg-orange-500/10">
                  {t('pages.webCachePosture.confirmed_primitives', '{{n}} confirmed', { n: confirmedPrimitives })}
                </span>
              )}
              {typeof poisonWindow === 'number' && poisonWindow > 0 && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-amber-500/40 text-amber-300 bg-amber-500/10">
                  {t('pages.webCachePosture.poison_window', 'Poison window ~{{n}}s', { n: poisonWindow })}
                </span>
              )}
              {typeof competitiveParity === 'number' && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-500/40 text-emerald-300 bg-emerald-500/10">
                  {t('pages.webCachePosture.competitive_parity', 'Parity {{n}}/100', { n: competitiveParity })}
                </span>
              )}
              {detectedVendor && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-sky-500/40 text-sky-300 bg-sky-500/10">
                  {detectedVendor}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="flex-1 space-y-4">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.webCachePosture.posture_dimensions', 'Posture dimensions')}</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {POSTURE_DIMS.map((d) => {
                const raw = dims[d.key]
                if (raw === undefined || raw === null) return null
                const n = Number(raw)
                const ok = n >= 80
                const warn = n >= 60 && n < 80
                const barColor = ok ? '#34d399' : warn ? '#fbbf24' : '#fb7185'
                return (
                  <div key={d.key} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] px-2.5 py-2">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-[10px] font-mono text-[var(--text-tertiary)]">{d.label}</span>
                      <span className="text-[10px] font-mono font-bold" style={{ color: barColor }}>{n}</span>
                    </div>
                    <div className="h-1 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                      <div className="h-full rounded-full transition-all" style={{ width: `${n}%`, backgroundColor: barColor }} />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {sevCounts.map(([sev, n]) => {
            const st = SEV_STYLE[sev]
            return (
              <div key={sev} className={`rounded-xl border ${st.bd} ${st.bg} px-3 py-2`}>
                <div className={`text-2xl font-bold ${st.text}`}>{n}</div>
                <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{sev}</div>
              </div>
            )
          })}
          </div>
        </div>
      </div>
      {attackChains.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400/80 mb-2">{t('pages.webCachePosture.attack_chains', 'Attack chains (confirmed primitives)')}</div>
          <div className="space-y-2">
            {attackChains.map((c) => (
              <div key={c.id || c.title} className="rounded-lg border border-rose-500/30 bg-rose-500/5 px-3 py-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono uppercase text-rose-300">{c.severity}</span>
                  {c.mitre && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {c.mitre}</span>}
                </div>
                <div className="text-xs font-medium text-[var(--text-primary)] mt-0.5">{c.title}</div>
                <p className="text-[11px] text-[var(--text-tertiary)] mt-1 leading-relaxed">{c.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {probeManifest && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.webCachePosture.probes_run', 'Probes enabled:')}</span>
          <span className="text-[10px] font-mono text-cyan-300/80">{probeManifest.probes_enabled ?? (Array.isArray(probeManifest.probes) ? probeManifest.probes.length : 0)}</span>
          {probeManifest.engine_version && (
            <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {probeManifest.engine_version}</span>
          )}
          {scanTelemetry && (
            <>
              <span className="text-[10px] font-mono text-[var(--text-disabled)]">·</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">{scanTelemetry.http_requests ?? 0} HTTP</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">{scanTelemetry.paths_tested ?? 0} paths</span>
              {scanTelemetry.scan_duration_ms != null && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">{scanTelemetry.scan_duration_ms}ms</span>
              )}
              {scanTelemetry.path_concurrency != null && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">{scanTelemetry.path_concurrency} path×</span>
              )}
            </>
          )}
        </div>
      )}
      {roadmap.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.webCachePosture.hardening_roadmap', 'Hardening roadmap')}</div>
          <ol className="space-y-1">
            {roadmap.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-[var(--text-tertiary)]">
                <span className="text-rose-400">{i + 1}.</span>{r}
              </li>
            ))}
          </ol>
        </div>
      )}
      <RiskMatrix matrix={riskMatrix} t={t} />
      <CdnPlaybook playbook={cdnPlaybook} t={t} />
      <TopPrimitives items={topPrimitives} t={t} />
      <DefenseControls controls={defenseControls} t={t} />
      <ComplianceMap map={complianceMap} t={t} />
      <CoverageManifest manifest={coverageManifest} t={t} />
      {cats.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.webCachePosture.weak_areas', 'Weak areas:')}</span>
          {cats.map((c) => (
            <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)]">
              {(CATEGORY_META[c] || CATEGORY_META.other).icon} {(CATEGORY_META[c] || CATEGORY_META.other).label}
            </span>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function WebCachePosture() {
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

  const detailFindings = useMemo(() => findings.filter((f) => !isSummary(f)), [findings])

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
  } = useWeissmanEnginePage(ENGINE, detailFindings)

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

  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [intensity, setIntensity] = useState('normal')
  const [paths, setPaths] = useState('/')
  const [extraHeaders, setExtraHeaders] = useState('')
  const [deceptionExts, setDeceptionExts] = useState('css, js, png, ico, txt, json')
  const [timeoutMs, setTimeoutMs] = useState(8000)
  const [concurrency, setConcurrency] = useState(8)
  const [includeInfo, setIncludeInfo] = useState(true)
  const [queryParam, setQueryParam] = useState('wzqp')
  const [pathConcurrency, setPathConcurrency] = useState(2)
  const [maxPaths, setMaxPaths] = useState(0)
  const [canaryDomain, setCanaryDomain] = useState('poison.example')

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
      intensity,
      include_info_findings: includeInfo,
      timeout_ms: Number(timeoutMs) || 8000,
      concurrency: Number(concurrency) || 8,
      paths: csvToArray(paths),
      deception_extensions: csvToArray(deceptionExts),
      query_param: queryParam.trim() || 'wzqp',
      path_concurrency: Number(pathConcurrency) || 2,
      max_paths: Number(maxPaths) || 0,
      canary_domain: canaryDomain.trim() || 'poison.example',
    }
    if (clientId) body.client_id = Number(clientId)
    const eh = csvToArray(extraHeaders)
    if (eh.length) body.headers = eh
    return body
  }, [target, toggles, intensity, includeInfo, timeoutMs, concurrency, paths, deceptionExts, clientId, extraHeaders, queryParam, pathConcurrency, maxPaths, canaryDomain])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.webCachePosture.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.webCachePosture.target_required', 'A target URL is required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.webCachePosture.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.webCachePosture.queued', 'Posture scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.webCachePosture.scan_failed', 'Scan failed'))
    }
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.webCachePosture.title', 'Web Cache Poisoning & Deception')}
      badge={t('pages.webCachePosture.badge', 'WEB CACHE / CDN EDGE')}
      badgeColor={ACCENT}
      subtitle={t('pages.webCachePosture.subtitle', 'v11 SEALED — 51 real-probe categories, configurable canary domain, duplicate-header + If-Modified-Since oracles, competitive coverage manifest. Cache-buster isolated. Zero fabrication.')}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-rose-500/30 text-rose-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.webCachePosture.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40 min-w-[180px]">
              <option value="">{t('pages.webCachePosture.select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.webCachePosture.target_url', 'Target URL')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.webCachePosture.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40">
              <option value="light">{t('pages.webCachePosture.intensity_light', 'Light')}</option>
              <option value="normal">{t('pages.webCachePosture.intensity_normal', 'Normal')}</option>
              <option value="aggressive">{t('pages.webCachePosture.intensity_aggressive', 'Aggressive')}</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #fb7185' : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-rose-500/40 text-rose-300 bg-rose-500/10 hover:bg-rose-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? t('pages.webCachePosture.scanning', '⟳ Scanning…') : t('pages.webCachePosture.run_scan', '▶ Run Posture Scan')}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-all">
            {showParams ? t('pages.webCachePosture.hide_params', '▾ Parameters') : t('pages.webCachePosture.show_params', '▸ Parameters')}
          </Button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.webCachePosture.probe_categories', 'Probe categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-rose-500" />
                        {tg.label}
                      </label>
                    ))}
                    <label className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer mt-1">
                      <input type="checkbox" checked={includeInfo} onChange={(e) => setIncludeInfo(e.target.checked)} className="accent-rose-500" />
                      {t('pages.webCachePosture.include_info', 'Include informational findings')}
                    </label>
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.paths', 'Paths to test')}</label>
                    <input type="text" value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="/ , /account , /search"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.extra_headers', 'Extra unkeyed headers')}</label>
                    <input type="text" value={extraHeaders} onChange={(e) => setExtraHeaders(e.target.value)} placeholder="X-Forwarded-Host, X-Custom-Host"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.canary_domain', 'Canary poison domain')}</label>
                    <input type="text" value={canaryDomain} onChange={(e) => setCanaryDomain(e.target.value)} placeholder="poison.example"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.query_param', 'Query unkeyed param name')}</label>
                    <input type="text" value={queryParam} onChange={(e) => setQueryParam(e.target.value)} placeholder="wzqp"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.deception_exts', 'Cache-deception extensions')}</label>
                    <input type="text" value={deceptionExts} onChange={(e) => setDeceptionExts(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.timeout_ms', 'Per-probe timeout (ms)')}</label>
                    <input type="number" min="1000" max="30000" step="500" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.path_concurrency', 'Parallel path fan-out')}</label>
                    <input type="number" min="1" max="4" step="1" value={pathConcurrency} onChange={(e) => setPathConcurrency(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.max_paths', 'Max paths (0=auto)')}</label>
                    <input type="number" min="0" max="16" step="1" value={maxPaths} onChange={(e) => setMaxPaths(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.webCachePosture.concurrency', 'Header probe concurrency')}</label>
                    <input type="number" min="1" max="16" step="1" value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-rose-500/40" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.webCachePosture.last_completed', 'Last completed: {{time}}', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.webCachePosture.select_client_warning', 'Select an in-scope client and target URL to run the posture scan.')}
        </div>
      )}

      <Scorecard summary={summary} t={t} />

      <WeissmanFindingsPanel
        findings={detailFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={detailFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && detailFindings.length === 0}
        loading={historyLoading && detailFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        showEmptyReady={status !== 'running' && detailFindings.length === 0}
        emptyReadyTitle={t('pages.webCachePosture.run_to_populate', 'Run a posture scan to assess cache-key security, unkeyed-input poisoning and web cache deception.')}
        emptyReadyBody={t('pages.webCachePosture.no_findings', 'No cache-poisoning or deception primitive observed — cache-key hygiene looks strong.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
