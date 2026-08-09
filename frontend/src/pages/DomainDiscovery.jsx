import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, Download } from 'lucide-react'
import { apiFetch } from '../utils/apiFetch'
import { SkeletonBar } from '../components/ui/Skeleton'

import EngineHubForensicHeader from '../components/engine/EngineHubForensicHeader'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const STAGE_COLORS = {
  'Primary Domain': '#22d3ee',
  'Certificate Transparency': '#8b5cf6',
  'DNS Enumeration': '#3b82f6',
  'Reverse IP Lookup': '#f97316',
  'Web Crawl': '#ec4899',
  'WHOIS Lookup': '#10b981',
  'Email Records': '#f59e0b',
  'Pattern Generation': '#6366f1',
}

function ConfidenceBadge({ confidence }) {
  const color = confidence > 0.8 ? '#4ade80' : confidence > 0.5 ? '#f59e0b' : '#6b7280'
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-mono"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {Math.round(confidence * 100)}%
    </span>
  )
}

function LiveBadge({ live, https }) {
  const { t } = useTranslation()
  if (!live) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400">
        {t('pages.domainDiscovery.offline')}
      </span>
    )
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-green-500/20 text-green-400">
      {https ? t('pages.domainDiscovery.live_badge') : t('pages.domainDiscovery.live')}
    </span>
  )
}

const STAGE_I18N_KEYS = {
  'Primary Domain': 'stage_primary',
  'Certificate Transparency': 'stage_ct',
  'DNS Enumeration': 'stage_dns',
  'Reverse IP Lookup': 'stage_reverse_ip',
  'Web Crawl': 'stage_crawl',
  'WHOIS Lookup': 'stage_whois',
  'Email Records': 'stage_email',
  'Pattern Generation': 'stage_pattern',
}

function StageBadge({ stage }) {
  const { t } = useTranslation()
  const color = STAGE_COLORS[stage] ?? '#6b7280'
  const label = STAGE_I18N_KEYS[stage]
    ? t(`pages.domainDiscovery.${STAGE_I18N_KEYS[stage]}`)
    : stage
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-mono border"
      style={{ borderColor: `${color}40`, color, backgroundColor: `${color}10` }}
    >
      {label}
    </span>
  )
}

function exportDomainsCsv(domains) {
  const header = ['domain', 'stage', 'live', 'https', 'confidence', 'http_status', 'ip_addresses', 'title']
  const rows = domains.map((d) => [
    d.domain,
    d.stage,
    d.live,
    d.https_available,
    d.confidence,
    d.http_status,
    Array.isArray(d.ip_addresses) ? d.ip_addresses.join(';') : '',
    d.title,
  ])
  downloadCsv(rows, header, 'weissman-domains')
}

// ─── Domain Card ─────────────────────────────────────────────────────────────

function DomainCard({ domain, selected, onSelect, onScanClick }) {
  const { t } = useTranslation()
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      className={`rounded-xl bg-[var(--bg-2)] backdrop-blur-md border p-4 transition-all duration-200 hover:shadow-[0_0_20px_rgba(0,0,0,0.3)] ${
        selected
          ? 'border-cyan-500/50 bg-cyan-950/20'
          : 'border-[var(--border-default)] hover:border-[var(--border-strong)]'
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onSelect(domain.domain)}
            className="w-4 h-4 rounded border-[var(--border-strong)] bg-[var(--bg-2)] text-cyan-500 focus:ring-cyan-500/40"
          />
          <span className="text-sm font-semibold text-white truncate">{domain.domain}</span>
        </div>
        <LiveBadge live={domain.live} https={domain.https_available} />
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <StageBadge stage={domain.stage} />
        <ConfidenceBadge confidence={domain.confidence} />
        {domain.http_status && (
          <span className="text-[10px] font-mono text-[var(--text-muted)]">
            HTTP {domain.http_status}
          </span>
        )}
      </div>

      {/* IPs */}
      {domain.ip_addresses && domain.ip_addresses.length > 0 && (
        <div className="mb-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.domainDiscovery.ips')} </span>
          <span className="text-[10px] font-mono text-[var(--text-tertiary)]">
            {domain.ip_addresses.slice(0, 3).join(', ')}
            {domain.ip_addresses.length > 3 && t('pages.domainDiscovery.more_ips', { count: domain.ip_addresses.length - 3 })}
          </span>
        </div>
      )}

      {/* Title */}
      {domain.title && (
        <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed line-clamp-2 mb-3">
          {domain.title}
        </p>
      )}

      {/* Action button */}
      <Button variant="unstyled"
        type="button"
        onClick={() => onScanClick(domain.domain)}
        disabled={!domain.live}
        className="w-full px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase tracking-wide border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/40 hover:text-cyan-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        {t('pages.domainDiscovery.add_to_scan')}
      </Button>
    </motion.div>
  )
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ result, selectedCount }) {
  const { t } = useTranslation()
  if (!result) return null
  return (
    <div className="flex flex-wrap items-center gap-4 p-4 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)]">
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-white">{result.total_discovered}</span>
        <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{t('pages.domainDiscovery.total_discovered')}</span>
      </div>
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-green-400">{result.live_domains}</span>
        <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{t('pages.domainDiscovery.live_domains')}</span>
      </div>
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-cyan-400">{selectedCount}</span>
        <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{t('pages.domainDiscovery.selected')}</span>
      </div>
      <div className="flex flex-col">
        <span className="text-lg font-semibold text-[var(--text-secondary)]">{result.stages_completed?.length || 0}</span>
        <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{t('pages.domainDiscovery.stages')}</span>
      </div>
    </div>
  )
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function DomainDiscovery() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [target, setTarget] = useState('')
  const [companyName, setCompanyName] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [selectedDomains, setSelectedDomains] = useState(new Set())
  const [filterStage, setFilterStage] = useState('all')
  const [filterLive, setFilterLive] = useState('all')
  const [search, setSearch] = useState('')
  const [toast, setToast] = useState(null)
  const [scanAllLoading, setScanAllLoading] = useState(false)
  const [lastSync, setLastSync] = useState(null)

  // Load clients
  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => {
        if (Array.isArray(d)) setClients(d)
      })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  // Set target from selected client
  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first)
    if (client.name) setCompanyName(client.name)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleDiscover = useCallback(async () => {
    if (!target.trim()) {
      showToast('error', t('pages.domainDiscovery.enter_target'))
      return
    }
    setLoading(true)
    setResult(null)
    setSelectedDomains(new Set())
    
    try {
      const d = await apiFetch('/api/discovery/domains', {
        method: 'POST',
        body: {
          target: target.trim(),
          company_name: companyName.trim() || null,
        },
      })
      setResult(d)
      setLastSync(new Date())
      showToast('info', t('pages.domainDiscovery.discovered_toast', { total: d.total_discovered, live: d.live_domains }))
    } catch (e) {
      showToast('error', e?.message ?? t('pages.domainDiscovery.network_error'))
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, companyName, showToast])

  const handleSelectDomain = useCallback((domain) => {
    setSelectedDomains((prev) => {
      const next = new Set(prev)
      if (next.has(domain)) {
        next.delete(domain)
      } else {
        next.add(domain)
      }
      return next
    })
  }, [])

  const handleSelectNone = useCallback(() => {
    setSelectedDomains(new Set())
  }, [])

  const handleScanSingle = useCallback(async (domain) => {
    if (!selectedClientId) {
      showToast('error', t('pages.domainDiscovery.select_client_first'))
      return
    }
    navigate(`/engines?target=${encodeURIComponent(domain)}`)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, navigate, showToast])

  const handleScanAll = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', t('pages.domainDiscovery.select_client_first'))
      return
    }
    if (selectedDomains.size === 0) {
      showToast('error', t('pages.domainDiscovery.select_one_domain'))
      return
    }
    setScanAllLoading(true)
    try {
      const d = await apiFetch('/api/scan/discovered-domains', {
        method: 'POST',
        body: {
          client_id: Number(selectedClientId),
          domains: Array.from(selectedDomains),
        },
      })
      showToast('info', t('pages.domainDiscovery.scan_queued', { count: d.domains_count, jobId: d.job_id }))
    } catch (e) {
      showToast('error', e?.message ?? t('pages.domainDiscovery.network_error'))
    } finally {
      setScanAllLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, selectedDomains, showToast])

  const filteredDomains = useMemo(() => {
    if (!result?.domains) return []
    const q = search.trim().toLowerCase()
    return result.domains.filter((d) => {
      if (filterStage !== 'all' && d.stage !== filterStage) return false
      if (filterLive === 'live' && !d.live) return false
      if (filterLive === 'offline' && d.live) return false
      if (q) {
        const hay = [d.domain, d.title, ...(d.ip_addresses || [])].join(' ').toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [result, filterStage, filterLive, search])

  const handleSelectAll = useCallback(() => {
    if (!result?.domains) return
    setSelectedDomains(new Set(filteredDomains.map((d) => d.domain)))
  }, [result, filteredDomains])

  const handleRefreshDiscovery = useCallback(async () => {
    if (!target.trim()) return
    await handleDiscover()
  }, [target, handleDiscover])

  const uniqueStages = result?.domains
    ? [...new Set(result.domains.map((d) => d.stage))]
    : []

  const stageLabel = useCallback((stage) => {
    const key = STAGE_I18N_KEYS[stage]
    return key ? t(`pages.domainDiscovery.${key}`) : stage
  }, [t])

  return (
    <div
      className="min-h-[100dvh] text-[var(--text-secondary)]"
      style={{
        background: 'var(--shell-bg)',
      }}
    >
      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-[var(--border-default)] bg-[var(--bg-3)] backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link to="/" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] text-xs font-mono transition-colors">
              {t('pages.domainDiscovery.dashboard')}
            </Link>
            <span className="text-[var(--text-disabled)] text-xs">|</span>
            <h1 className="text-sm font-bold tracking-tight text-white">{t('pages.domainDiscovery.title')}</h1>
            <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-widest">
              {t('pages.domainDiscovery.tagline')}
            </span>
          </div>

          {/* Client selector */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.domainDiscovery.client')}</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
            >
              <option value="">{t('pages.domainDiscovery.select_client')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <ShellScanActions
              onRefresh={handleRefreshDiscovery}
              onExport={() => exportDomainsCsv(filteredDomains)}
              refreshLoading={loading}
              refreshDisabled={!target.trim()}
              exportDisabled={!filteredDomains.length}
            />
          </div>
        </div>
      </header>

      {/* Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.sev === 'error'
                ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
                : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-screen-2xl mx-auto px-4 py-6 space-y-6">
        <EngineHubForensicHeader
          evidence={t('pages.domainDiscovery.evidence_notice')}
          engineId="discovery_engine"
        />
        {lastSync && (
          <p className="text-[10px] font-mono text-[var(--text-muted)] -mt-4">
            {t('weissmanFindings.last_updated', { time: lastSync.toLocaleString() })}
          </p>
        )}

        {/* Discovery form */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 space-y-4"
        >
          <h2 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.domainDiscovery.config_heading')}</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-[11px] font-mono text-[var(--text-tertiary)] uppercase tracking-wider mb-1">
                {t('pages.domainDiscovery.target_label')}
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={t('pages.domainDiscovery.target_placeholder')}
                className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-[var(--text-tertiary)] uppercase tracking-wider mb-1">
                {t('pages.domainDiscovery.company_optional')}
              </label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder={t('pages.domainDiscovery.company_placeholder')}
                className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
            <div className="flex items-end">
              <Button variant="unstyled"
                type="button"
                onClick={handleDiscover}
                disabled={loading || !target.trim()}
                className="w-full px-5 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {loading ? t('pages.domainDiscovery.discovering') : t('pages.domainDiscovery.discover')}
              </Button>
            </div>
          </div>
          <p className="text-[11px] text-[var(--text-muted)]">
            {t('pages.domainDiscovery.stages_hint')}
          </p>
        </motion.section>

        {loading && (
          <div className="space-y-4">
            <SkeletonBar className="h-20" />
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <SkeletonBar key={i} className="h-36" />
              ))}
            </div>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <>
            {/* Stats */}
            <StatsBar result={result} selectedCount={selectedDomains.size} />

            {/* Actions bar */}
            <div className="flex flex-wrap items-center justify-between gap-4">
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-disabled)]" />
                  <input
                    type="search"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    aria-label={t('pages.domainDiscovery.search_placeholder')}
                    placeholder={t('pages.domainDiscovery.search_placeholder')}
                    className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg pl-8 pr-2 py-1 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40 w-44"
                  />
                </div>
                <select
                  value={filterStage}
                  onChange={(e) => setFilterStage(e.target.value)}
                  className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
                >
                  <option value="all">{t('pages.domainDiscovery.filter_all_stages')}</option>
                  {uniqueStages.map((s) => (
                    <option key={s} value={s}>{stageLabel(s)}</option>
                  ))}
                </select>
                <select
                  value={filterLive}
                  onChange={(e) => setFilterLive(e.target.value)}
                  className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
                >
                  <option value="all">{t('pages.domainDiscovery.filter_all_status')}</option>
                  <option value="live">{t('pages.domainDiscovery.filter_live_only')}</option>
                  <option value="offline">{t('pages.domainDiscovery.filter_offline_only')}</option>
                </select>
                <span className="text-[10px] font-mono text-[var(--text-muted)]">
                  {t('pages.domainDiscovery.shown', { count: filteredDomains.length })}
                </span>
              </div>

              {/* Selection actions */}
              <div className="flex items-center gap-2">
                <Button variant="unstyled"
                  type="button"
                  onClick={() => exportDomainsCsv(filteredDomains)}
                  disabled={filteredDomains.length === 0}
                  className="inline-flex items-center gap-1 px-3 py-1 rounded-lg text-[11px] font-mono border border-emerald-500/30 text-emerald-300/80 hover:bg-emerald-500/10 disabled:opacity-40"
                >
                  <Download className="w-3.5 h-3.5" />
                  {t('pages.domainDiscovery.export_csv')}
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={handleSelectAll}
                  className="px-3 py-1 rounded-lg text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
                >
                  {t('pages.domainDiscovery.select_all_count', { count: filteredDomains.length })}
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={handleSelectNone}
                  className="px-3 py-1 rounded-lg text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
                >
                  {t('pages.domainDiscovery.deselect_all')}
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={handleScanAll}
                  disabled={scanAllLoading || selectedDomains.size === 0 || !selectedClientId}
                  className="px-4 py-1.5 rounded-lg text-[11px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {scanAllLoading ? t('pages.domainDiscovery.scanning') : t('pages.domainDiscovery.scan_all_selected', { count: selectedDomains.size })}
                </Button>
              </div>
            </div>

            {/* Domain grid */}
            <AnimatePresence mode="popLayout">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {filteredDomains.map((domain) => (
                  <DomainCard
                    key={domain.domain}
                    domain={domain}
                    selected={selectedDomains.has(domain.domain)}
                    onSelect={handleSelectDomain}
                    onScanClick={handleScanSingle}
                  />
                ))}
              </div>
            </AnimatePresence>

            {filteredDomains.length === 0 && (
              <div className="text-center py-12">
                <p className="text-[var(--text-muted)] font-mono text-sm">{t('pages.domainDiscovery.no_filter_match')}</p>
              </div>
            )}
          </>
        )}

        {/* Empty state */}
        {!result && !loading && (
          <div className="text-center py-16">
            <div className="text-4xl mb-4">🌐</div>
            <h3 className="text-lg font-semibold text-[var(--text-secondary)] mb-2">{t('pages.domainDiscovery.empty_title')}</h3>
            <p className="text-[var(--text-muted)] text-sm max-w-md mx-auto">
              {t('pages.domainDiscovery.empty_body')}
            </p>
          </div>
        )}
      </main>
    </div>
  )
}
