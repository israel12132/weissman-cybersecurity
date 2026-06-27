import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { ENGINES_BY_ID, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch, resolveEventSourceUrl } from '../lib/apiBase'
import { downloadBytes } from '../lib/pdfExport'
import { useProductionEngines } from '../lib/useProductionEngines'
import { isTopTierEngine } from '../lib/topTierEngineProfiles'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { normalizeIntegrations, buildScanPayload } from '../lib/engineClientPrefill'
import { getEngineParams } from '../lib/engineParamDefs.js'
import EngineScanParamsPanel from '../components/engine/EngineScanParamsPanel'
import { useEngineScanParams } from '../hooks/useEngineScanParams'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'

const MAX_LINES_REAL = 1000
const DEDICATED_ENGINE_IDS = new Set(strategicEnginesNeedingDedicatedPage().map((e) => e.id))

// ─── Engine type classification ────────────────────────────────────────────────

const ENGINE_TYPE_MAP = {
  live_probe: new Set([
    'osint','asm','recon','leak_hunter','discovery_engine',
    'bola_idor','graphql_attack','jwt_attack','oauth_oidc','http_smuggling',
    'prototype_pollution','ssrf_advanced','xxe','ssti','file_upload',
    'websocket_attack','cache_poisoning','http_feedback_fuzz',
    'aws_attack','cloud_posture','azure_attack','gcp_attack','k8s_container','iac_misconfig',
    'serverless_attack','scada_ics','iot_firmware','ble_rf',
    'edr_evasion','waf_bypass','timing_sidechannel','antiforensics','stealth_engine',
    'pki_tls','pqc_scanner','password_spray','kerberoasting','saml_attack','crypto_engine','email_dns_posture',
    'bgp_dns_hijacking','ipv6_attack','mtls_grpc','smb_netbios',
    'cicd_pipeline','container_registry','sbom_analyzer','typosquatting_monitor',
    'kill_chain','oast_oob','deception_honeypot','digital_twin','zero_day_prediction',
    'threat_emulation','microsecond_timing','semantic_ai_fuzz','ai_adversarial_redteam',
    'llm_redteam','adversarial_ml','autonomous_pentest','nexus_sovereign_swarm','llm_path_fuzz','supply_chain',
    'cors_misconfiguration','swagger_abuse','soap_injection','odata_injection',
    'css_injection','template_injection_adv','http_parameter_pollution','api_mass_assignment',
    'clickjacking_engine','subdomain_takeover','file_inclusion_rfi','deserialization_net',
    'api_rate_limit_bypass','graphql_subscription_attack','webrtc_attack',
    'browser_extension_attack','web3_dapp_attack','api_gateway_bypass',
    'arp_spoofing_engine','vlan_hopping_attack','dhcp_attack_engine','dns_cache_poisoning',
    'ntp_amplification','snmp_exploitation','rdp_attack_engine','ldap_injection_engine',
    'voip_sip_attack','wifi_attack_engine','bluetooth_attack_engine',
    'ospf_bgp_hijack','mpls_vpn_attack','lte_5g_attack','network_covert_channel',
    'wpa3_attack_engine','tor_exit_attack','protocol_downgrade','network_baseline_anomaly',
    'packet_injection_engine','network_tap_advanced','multicast_attack','nat_traversal_attack',
    'dnp3_attack','bacnet_attack','zigbee_attack','iec61850_attack','satellite_comm_attack','rfid_nfc_attack',
    'threat_intel_fusion','attack_surface_quantify','passive_dns_forensics','dark_web_monitor',
    'lambda_escape','terraform_state_attack','cloudformation_injection','service_mesh_attack',
    'cloud_audit_evasion','ecr_registry_attack','multi_cloud_pivot','cloud_worm_propagation',
    'serverless_injection','cloud_data_exfil','cloud_network_attack','cloud_privilege_persistence',
    'padding_oracle_attack','hash_extension_attack','ecdsa_nonce_bias','rsa_timing_attack',
    'mfa_bypass_engine','credential_stuffing','kerberos_attack_suite','zero_trust_bypass',
    'pki_hierarchy_attack','session_fixation_adv','password_hash_crack','quantum_key_attack',
    'password_spray_advanced',
    'android_malware_engine','ios_exploit_engine','mobile_mitm','ssl_pinning_bypass',
    'android_intent_attack','ios_url_scheme_attack','mobile_overlay_attack','sim_swap_engine',
    'mobile_banking_trojan','app_store_attack','mdm_bypass_engine','bluetooth_mobile_attack',
    'nfc_relay_attack','mobile_spyware_engine','react_native_attack',
    'github_actions_attack','compiler_backdoor','open_source_backdoor','cdn_poisoning_engine',
    'software_signing_attack','build_system_compromise','dependency_confusion','update_hijacking',
    'sbom_forgery_engine','third_party_api_attack','iac_supply_chain',
  ]),
  ttp_emulation: new Set([
    'apt28_techniques','apt29_techniques','apt41_techniques','lazarus_group_ttps',
    'volt_typhoon_ttps','scattered_spider_ttps','salt_typhoon_ttps','fin7_techniques',
    'conti_ransomware_ttps','lockbit_techniques','cl0p_techniques','blackcat_alphv_ttps',
    'midnight_blizzard_ttps','earth_longzhi_ttps','equation_group_ttps','sandworm_techniques',
    'carbon_spider_ttps','wizard_spider_ttps','unc2452_ttps','unc3944_ttps','quantum_sovereign_nexus',
  ]),
  malware_emulation: new Set([
    'bootkit_uefi','fileless_malware_engine','polymorphic_engine','botnet_c2_engine',
    'keylogger_engine','spyware_stalkerware','worm_propagation','rce_exploit_engine',
    'persistence_mechanism','lateral_movement_engine','data_staging_engine',
    'exploit_kit_engine','trojan_dropper','macro_malware',
    'process_hollowing','living_off_land','heap_exploitation',
  ]),
  social_sim: new Set([
    'spear_phishing_engine','vishing_engine','smishing_engine','qr_phishing',
    'deepfake_voice_engine','business_email_compromise','watering_hole_attack',
    'pretexting_engine','insider_threat_engine','brand_impersonation','fake_update_engine',
    'linkedin_phishing','callback_phishing','physical_social_eng','typosquatting_phishing',
    'adversarial_simulation',
  ]),
  ai_probe: new Set([
    'llm_jailbreak','prompt_injection_chain','model_inversion_attack','ai_supply_chain_attack',
    'llm_agent_hijack','rag_poisoning_engine','adversarial_examples','data_poisoning_engine',
    'deepfake_synthesis','llm_dos_attack','multimodal_ai_attack','ai_bias_exploit',
    'gpt_plugin_attack','autonomous_ai_escape','llm_memory_extraction','neural_backdoor_detect',
    'ai_watermark_bypass',    'federated_learning_attack','llm_red_team_advanced','model_stealing_engine',
    'nexus_sovereign_swarm',
  ]),
  data_exfil: new Set([
    'dns_exfil_engine','http_covert_exfil','cloud_exfil_engine','encrypted_exfil',
    'acoustic_exfil','em_exfil_engine','optical_exfil','cache_timing_exfil',
    'keyboard_acoustic','screen_capture_exfil','clipboard_hijack','database_exfil',
    'email_exfil','insider_exfil','storage_covert_channel',
  ]),
}

function getEngineType(id) {
  for (const [type, set] of Object.entries(ENGINE_TYPE_MAP)) {
    if (set.has(id)) return type
  }
  return 'live_probe'
}

const ENGINE_TYPE_META = {
  live_probe:       { label: 'Live Probe',          color: '#22d3ee', bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30',   icon: '⚡' },
  ttp_emulation:    { label: 'TTP Emulation',        color: '#ef4444', bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: '🎯' },
  malware_emulation:{ label: 'Behavioral Emulation', color: '#dc2626', bg: 'bg-red-900/20',    border: 'border-red-700/30',    icon: '🦠' },
  social_sim:       { label: 'Social Simulation',    color: '#d97706', bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  icon: '🎭' },
  ai_probe:         { label: 'AI/LLM Probe',         color: '#ec4899', bg: 'bg-pink-500/10',   border: 'border-pink-500/30',   icon: '🤖' },
  data_exfil:       { label: 'Exfil Technique',      color: '#0891b2', bg: 'bg-cyan-900/20',   border: 'border-cyan-700/30',   icon: '💾' },
}

// ─── Terminal ──────────────────────────────────────────────────────────────────

function Terminal({ lines }) {
  const { t } = useTranslation()
  const termRef = useRef(null)
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight
    }
  }, [lines])

  const copyAll = useCallback(() => {
    navigator.clipboard?.writeText(lines.join('\n')).catch(() => {})
  }, [lines])

  return (
    <div className="relative">
      {lines.length > 0 && (
        <button type="button" onClick={copyAll}
          className="absolute top-2 right-2 z-10 text-[10px] font-mono text-white/30 hover:text-cyan-400 bg-black/60 px-2 py-1 rounded border border-white/10 transition-colors">
          Copy
        </button>
      )}
      <div ref={termRef} className="h-80 overflow-auto rounded-xl bg-black/80 border border-white/5 p-3 font-mono text-[11px] leading-relaxed">
        {lines.length === 0 ? (
          <span className="text-white/20">{t('engines.detail_terminal_idle')}</span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={
              line.includes('[ERROR]') || line.includes('ERROR')
                ? 'text-red-400'
                : line.includes('[WARN]') || line.includes('WARN')
                  ? 'text-yellow-400'
                  : line.includes('Completed') || line.includes('completed') || line.includes('[OK]')
                    ? 'text-[#4ade80]'
                    : line.includes('finding') || line.includes('FINDING')
                      ? 'text-amber-300'
                      : 'text-[#4ade80]/80'
            }>
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Dynamic param field ────────────────────────────────────────────────────────

// ─── Findings panel ────────────────────────────────────────────────────────────

function FindingBadge({ severity }) {
  const s = (severity || 'info').toLowerCase()
  const styles = {
    critical: 'bg-red-900/60 text-red-300 border-red-700/50',
    high:     'bg-orange-900/60 text-orange-300 border-orange-700/50',
    medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700/50',
    low:      'bg-blue-900/60 text-blue-300 border-blue-700/50',
    info:     'bg-slate-800/60 text-slate-300 border-slate-600/50',
  }
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${styles[s] || styles.info}`}>{s}</span>
  )
}

function FindingsTable({ findings }) {
  if (!findings.length) return null
  return (
    <div className="space-y-2 max-h-96 overflow-auto">
      {findings.map((f, i) => (
        <div key={i} className="rounded-lg bg-black/40 border border-white/10 p-3 space-y-1">
          <div className="flex items-start justify-between gap-2">
            <span className="text-sm font-semibold text-white/90">{f.title || f.type || 'Finding'}</span>
            <FindingBadge severity={f.severity} />
          </div>
          {f.description && <p className="text-[11px] text-white/55 font-mono leading-relaxed">{f.description}</p>}
          <div className="flex flex-wrap gap-3 mt-1">
            {f.mitre_attack && (
              <a href={`https://attack.mitre.org/techniques/${(f.mitre_attack||'').replace('.','/')}`} target="_blank" rel="noopener noreferrer" className="text-[10px] font-mono text-cyan-400 hover:underline">{f.mitre_attack}</a>
            )}
            {f.url && <span className="text-[10px] font-mono text-white/40 truncate max-w-xs">{f.url}</span>}
            {f.target && <span className="text-[10px] font-mono text-white/40">{f.target}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

function useFindings() {
  const [findings, setFindings] = useState([])
  const addFinding = useCallback((data) => {
    if (data?.type && (data.title || data.description)) {
      setFindings((prev) => [...prev, data])
    }
  }, [])
  const reset = useCallback(() => setFindings([]), [])
  return { findings, addFinding, reset }
}

// ─── Run history ───────────────────────────────────────────────────────────────

const HISTORY_KEY = (id) => `engine_run_history_${id}`
const MAX_HISTORY = 10

function loadHistory(engineId) {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY(engineId)) || '[]') } catch { return [] }
}

function saveRun(engineId, { target, status, findingsCount, jobId }) {
  const history = loadHistory(engineId)
  history.unshift({ target, status, findingsCount, jobId, ts: new Date().toISOString() })
  localStorage.setItem(HISTORY_KEY(engineId), JSON.stringify(history.slice(0, MAX_HISTORY)))
}

function StatCard({ label, value, sub, accent = '#22d3ee', icon }) {
  return (
    <div
      className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] to-black/50 backdrop-blur-xl p-4 transition-all duration-300 hover:border-white/15"
      style={{ boxShadow: `inset 0 1px 0 ${accent}15` }}
    >
      <div className="absolute top-0 inset-x-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}50, transparent)` }} />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-white/40 mb-1.5">{label}</p>
          <p className="text-xl font-bold text-white tracking-tight truncate">{value}</p>
          {sub && <p className="text-[10px] font-mono text-white/35 mt-1 truncate">{sub}</p>}
        </div>
        {icon && <span className="text-lg opacity-60 shrink-0">{icon}</span>}
      </div>
    </div>
  )
}

function mapServerHistoryJob(job) {
  return {
    target: job.target || '',
    status: job.status || 'unknown',
    findingsCount: job.findings_count ?? job.findingsCount ?? 0,
    jobId: job.job_id ?? job.jobId ?? '',
    ts: job.created_at ?? job.ts ?? new Date().toISOString(),
    source: job.source || 'server',
  }
}

function RunHistoryPanel({ engineId, emptyLabel }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [fromServer, setFromServer] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=20`)
        const data = await r.json().catch(() => null)
        if (!cancelled && r.ok && Array.isArray(data?.jobs) && data.jobs.length > 0) {
          setHistory(data.jobs.map(mapServerHistoryJob))
          setFromServer(true)
          setLoading(false)
          return
        }
      } catch {
        /* fall through to localStorage */
      }
      if (!cancelled) {
        setHistory(loadHistory(engineId))
        setFromServer(false)
        setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [engineId])

  if (loading) return <p className="text-[11px] font-mono text-white/25">Loading run history…</p>
  if (!history.length) return <p className="text-[11px] font-mono text-white/25">{emptyLabel}</p>
  return (
    <div className="space-y-2">
      {!fromServer && (
        <p className="text-[10px] font-mono text-white/20 mb-2">Showing local browser history (server unavailable).</p>
      )}
      {history.map((r, i) => (
        <div key={i} className="flex items-center gap-3 text-[11px] font-mono text-white/50 flex-wrap">
          <span className={r.status === 'completed' ? 'text-[#4ade80]' : 'text-red-400'}>{r.status}</span>
          <span className="text-white/30">{new Date(r.ts).toLocaleString()}</span>
          {r.target && <span className="text-cyan-400/60 truncate max-w-[200px]">{r.target}</span>}
          {r.findingsCount > 0 && <span className="text-amber-300">{r.findingsCount} finding{r.findingsCount !== 1 ? 's' : ''}</span>}
          {r.jobId && <span className="text-white/20 truncate max-w-[100px]">{r.jobId}</span>}
        </div>
      ))}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function EngineDetail() {
  const { t } = useTranslation()
  const { engineId } = useParams()
  const { isProduction } = useProductionEngines()
  const engine        = ENGINES_BY_ID[engineId] ?? null
  const groupDef      = engine ? ENGINE_GROUPS[engine.group] : null
  const engineType    = getEngineType(engineId || '')
  const engineTypeMeta= ENGINE_TYPE_META[engineType] || ENGINE_TYPE_META.live_probe
  const extraParamDefs= useMemo(() => getEngineParams(engine), [engine])
  const [runHistory, setRunHistory] = useState([])
  const lastHistoryRun= runHistory[0] ?? null

  const [target, setTarget]               = useState('')
  const [timeoutSec, setTimeoutSec]       = useState(120)
  const [running, setRunning]             = useState(false)
  const [lines, setLines]                 = useState([])
  const { findings, addFinding, reset: resetFindings } = useFindings()
  const [jobId, setJobId]                 = useState(null)
  const [lastRunStatus, setLastRunStatus] = useState(null)
  const esRef = useRef(null)
  const [clients, setClients]             = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const { extraParams, setParam: setExtraParam } = useEngineScanParams(engineId, clientIntegrations)
  useSyncHubScanParams(engineId, extraParams)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [toast, setToast]                 = useState(null)
  const [activeTab, setActiveTab]         = useState('output')
  const [historyLoading, setHistoryLoading] = useState(false)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  const reloadHistory = useCallback(async () => {
    if (!engineId) return
    setHistoryLoading(true)
    try {
      const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=20`)
      const data = await r.json().catch(() => null)
      if (r.ok && Array.isArray(data?.jobs) && data.jobs.length > 0) {
        setRunHistory(data.jobs.map(mapServerHistoryJob))
        return
      }
      setRunHistory(loadHistory(engineId))
    } catch {
      setRunHistory(loadHistory(engineId))
    } finally {
      setHistoryLoading(false)
    }
  }, [engineId])

  useEffect(() => {
    reloadHistory()
  }, [engineId, lastRunStatus, reloadHistory])

  useEffect(() => {
    if (!selectedClientId) {
      setClientIntegrations(null)
      return
    }
    let cancelled = false
    apiFetch(`/api/clients/${selectedClientId}/integrations`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (!cancelled && d) setClientIntegrations(normalizeIntegrations(d)) })
      .catch(() => { if (!cancelled) setClientIntegrations(null) })
    return () => { cancelled = true }
  }, [selectedClientId])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleRun = useCallback(async () => {
    if (!isProduction(engineId)) {
      showToast('error', t('engines.catalog_only_run_disabled'))
      return
    }
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    if (engine?.requiresTarget && !target.trim()) { showToast('error', 'Enter a target URL'); return }
    setRunning(true)
    setLines([])
    resetFindings()
    setJobId(null)
    setLastRunStatus(null)

    const body = buildScanPayload(engineId, {
      clientId: selectedClientId,
      target: target.trim(),
      integrations: clientIntegrations,
      extraParams,
    })
    body.timeout = timeoutSec
    if (body.stealth_mode) body.stealth = body.stealth_mode
    if (body.llm_base_url) body.ai_endpoint = JSON.stringify({ base_url: body.llm_base_url, model: body.llm_model || '' })

    try {
      const { ok, data: d, status } = await postScan(body)
      if (!ok) {
        showToast('error', d.detail || d.error || `Scan failed (${status})`)
        setRunning(false)
        return
      }
      const jid = d.job_id || ''
      setJobId(jid)
      setLines([`> Job queued: ${jid || '(pending)'}`, `> Connecting to live stream...`])
      if (jid) {
        const streamPath = engineId === 'poe_synthesis'
          ? `/api/poe-scan/stream/${encodeURIComponent(jid)}`
          : `/api/telemetry/stream?job_id=${encodeURIComponent(jid)}`
        const url = await resolveEventSourceUrl(streamPath)
        if (esRef.current) esRef.current.close()
        const es = new EventSource(url, { withCredentials: true })
        esRef.current = es
        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data || '{}')
            const line = data.message || data.error || ''
            if (line) setLines((prev) => [...prev.slice(-MAX_LINES_REAL), `> ${line}`])
            if (data.finding) addFinding(data.finding)
            if (data.findings && Array.isArray(data.findings)) data.findings.forEach(addFinding)
            if (data.status === 'completed' || data.status === 'failed') {
              const status = data.status
              setLastRunStatus(status)
              setRunning(false)
              es.close()
              setLines((prev) => [...prev, `> [${status.toUpperCase()}] Job ${jid} finished.`])
            }
          } catch {}
        }
        es.onerror = () => { setRunning(false); es.close(); setLastRunStatus('error') }
      } else {
        setLines((prev) => [...prev, '> (No job stream — check backend logs)'])
        setRunning(false)
        setLastRunStatus('queued')
      }
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setRunning(false)
    }
  }, [selectedClientId, target, timeoutSec, engineId, engine, extraParams, showToast, resetFindings, addFinding, isProduction, t])

  const handleStop = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    setRunning(false)
    setLines((prev) => [...prev, '> [Stopped by operator]'])
    setLastRunStatus('stopped')
  }, [])

  useEffect(() => {
    if (lastRunStatus && jobId !== null) {
      saveRun(engineId, { target, status: lastRunStatus, findingsCount: findings.length, jobId: jobId || '' })
    }
  }, [lastRunStatus]) // eslint-disable-line

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const handleExport = useCallback(() => {
    const payload = {
      engine: engineId,
      label: engine?.label,
      exported_at: new Date().toISOString(),
      job_id: jobId,
      last_run_status: lastRunStatus,
      findings,
      run_history: runHistory,
    }
    const bytes = new TextEncoder().encode(JSON.stringify(payload, null, 2))
    downloadBytes(bytes, `${engineId}-export.json`, 'application/json')
    showToast('info', 'Export downloaded')
  }, [engineId, engine?.label, jobId, lastRunStatus, findings, runHistory, showToast])

  const exportFindingsCsv = useCallback(() => {
    if (!findings.length) return
    exportStandardFindingsCsv(findings, `${engineId}-findings`)
  }, [findings, engineId])

  const {
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    filteredFindings: filteredSessionFindings,
    counts: findingCounts,
  } = useFindingsWorkbench(findings, { csvPrefix: `${engineId}-findings` })

  const engineRunnable = isProduction(engineId)
  const healthLabel = engineRunnable
    ? t('engines.detail_health_live')
    : t('engines.detail_health_catalog')
  const healthAccent = isProduction(engineId) ? '#4ade80' : '#9ca3af'
  const lastRunDisplay = lastHistoryRun
    ? new Date(lastHistoryRun.ts).toLocaleString()
    : t('engines.detail_never_run')
  const totalFindings = findings.length || (lastHistoryRun?.findingsCount ?? 0)

  if (!engine) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-300 font-mono p-8">
        <p className="text-red-400 text-lg mb-4">{t('engines.detail_unknown')}: <code>{engineId}</code></p>
        <Link to="/engines" className="text-cyan-400 hover:underline">{t('engines.detail_back_matrix')}</Link>
      </div>
    )
  }

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 120% 80% at 50% -5%, #1e293b 0%, #0f172a 40%, #020617 70%, #000 100%)' }}
    >
      <header className="sticky top-0 z-20 border-b border-white/[0.08] bg-black/65 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3 flex-wrap min-w-0">
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
            {t('engines.detail_back_matrix')}
          </Link>
          <span className="text-white/15 text-xs">|</span>
          {groupDef && (
            <span
              className="text-[10px] font-mono px-2 py-0.5 rounded-md uppercase tracking-widest border"
              style={{ color: groupDef.color, borderColor: `${groupDef.color}40`, backgroundColor: `${groupDef.color}10` }}
            >
              {groupDef.label}
            </span>
          )}
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md uppercase tracking-widest border ${engineTypeMeta.bg} ${engineTypeMeta.border}`} style={{ color: engineTypeMeta.color }}>
            {engineTypeMeta.icon} {engineTypeMeta.label}
          </span>
          {isTopTierEngine(engineId) && (
            <Link to={`/engines/top-tier/${engineId}`} className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-rose-500/40 text-rose-300 hover:bg-rose-500/10">Top-Tier</Link>
          )}
          {engineId === 'risk_superposition_collapse' && (
            <Link to="/superposition-collapse" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-violet-500/40 text-violet-300 hover:bg-violet-500/10">Superposition Command Center</Link>
          )}
          {engineId === 'nexus_sovereign_swarm' && (
            <Link to="/nexus-swarm" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-violet-500/40 text-violet-300 hover:bg-violet-500/10">Swarm Command Center</Link>
          )}
          {engineId === 'graphql_attack' && (
            <Link to="/graphql-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-pink-500/40 text-pink-300 hover:bg-pink-500/10">API Security Command Center</Link>
          )}
          {engineId === 'websocket_attack' && (
            <Link to="/websocket-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">WebSocket Security Command Center</Link>
          )}
          {engineId === 'iac_misconfig' && (
            <Link to="/iac-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">IaC Security Center</Link>
          )}
          {engineId === 'oauth_oidc' && (
            <Link to="/identity-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">Identity Security Center</Link>
          )}
          {engineId === 'http_smuggling' && (
            <Link to="/http-smuggling" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-orange-500/40 text-orange-300 hover:bg-orange-500/10">HTTP Desync Posture</Link>
          )}
          {engineId === 'cache_poisoning' && (
            <Link to="/cache-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-rose-500/40 text-rose-300 hover:bg-rose-500/10">Web Cache Posture</Link>
          )}
          {engineId === 'cloud_posture' && (
            <Link to="/cloud-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-orange-500/40 text-orange-300 hover:bg-orange-500/10">CSPM Command Center</Link>
          )}
          {engineId === 'email_dns_posture' && (
            <Link to="/email-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">Email Trust Posture</Link>
          )}
          {engineId === 'smb_netbios' && (
            <Link to="/smb-netbios" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-blue-500/40 text-blue-300 hover:bg-blue-500/10">SMB Command Center</Link>
          )}
          {DEDICATED_ENGINE_IDS.has(engineId) && (
            <Link to={`/engines/business/${engineId}`} className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">Business Profile</Link>
          )}
          </div>
          <ShellScanActions
            onRefresh={reloadHistory}
            onExport={exportFindingsCsv}
            refreshLoading={historyLoading}
            exportDisabled={!findings.length}
          />
        </div>
      </header>

      {/* ── Toast ──────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div key={toast.id} initial={{ opacity:0, y:-10 }} animate={{ opacity:1, y:0 }} exit={{ opacity:0, y:-10 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'
            }`}>
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-6xl mx-auto px-4 py-8 space-y-6">
        <AgentRequiredGate engineId={engineId}>
        <EvidenceNotice>{t('pages.engineDetail.evidence_notice')}</EvidenceNotice>

        {/* ── Hero header ─────────────────────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-gradient-to-br from-white/[0.07] via-black/45 to-black/70 backdrop-blur-xl p-6 md:p-8"
        >
          <div
            className="absolute inset-x-0 top-0 h-px"
            style={{ background: `linear-gradient(90deg, transparent, ${groupDef?.color ?? '#22d3ee'}70, transparent)` }}
          />
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="space-y-4 min-w-0 flex-1">
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-3xl md:text-4xl font-bold text-white tracking-tight">{engine.label}</h1>
                <code className="text-[11px] font-mono text-white/35 bg-black/40 px-2 py-0.5 rounded-md border border-white/[0.08]">{engine.id}</code>
                {running && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 animate-pulse">
                    ⟳ {t('engines.running')}
                  </span>
                )}
                {lastRunStatus && !running && (
                  <span className={`text-[10px] font-mono px-2.5 py-1 rounded-md border ${
                    lastRunStatus === 'completed' ? 'bg-green-500/10 border-green-500/30 text-green-400'
                    : lastRunStatus === 'stopped'  ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                    : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
                    {lastRunStatus.toUpperCase()}
                  </span>
                )}
              </div>
              <p className="text-sm md:text-base text-white/55 leading-relaxed max-w-3xl">{engine.description}</p>
              <div className="flex flex-wrap gap-2">
                {engine.requiresTarget && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-white/10 text-white/40 bg-white/[0.04]">
                    {t('engines.detail_requires_target')}
                  </span>
                )}
                {engine.mitre && (
                  <a
                    href={`https://attack.mitre.org/techniques/${engine.mitre.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-white/10 text-cyan-400/80 hover:text-cyan-300 bg-cyan-500/[0.04]"
                  >
                    {engine.mitre}
                  </a>
                )}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleRun}
                disabled={running || !engineRunnable}
                title={!engineRunnable ? t('engines.catalog_only_run_disabled') : undefined}
                className="px-5 py-2.5 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/30 hover:shadow-[0_0_24px_rgba(34,211,238,0.15)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {running ? t('engines.running') : `▶ ${t('engines.detail_run_engine')}`}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('history')}
                className="px-4 py-2.5 rounded-xl font-mono text-sm border border-white/12 text-white/55 hover:text-white/85 hover:border-white/25 hover:bg-white/[0.04] transition-all"
              >
                {t('engines.detail_view_history')}
              </button>
              <button
                type="button"
                onClick={handleExport}
                className="px-4 py-2.5 rounded-xl font-mono text-sm border border-emerald-500/30 text-emerald-300/90 hover:bg-emerald-500/10 hover:border-emerald-400/40 transition-all"
              >
                ↓ {t('engines.detail_export')}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-8">
            <StatCard
              label={t('engines.detail_stat_last_run')}
              value={lastRunDisplay}
              sub={lastHistoryRun?.status ? String(lastHistoryRun.status) : (jobId ? `Job ${jobId}` : undefined)}
              accent="#a78bfa"
              icon="⏱"
            />
            <StatCard
              label={t('engines.detail_stat_findings')}
              value={String(totalFindings)}
              sub={findings.length > 0 ? `${findings.length} this session` : undefined}
              accent="#f59e0b"
              icon="⚠"
            />
            <StatCard
              label={t('engines.detail_stat_health')}
              value={healthLabel}
              sub={isProduction(engineId) ? 'GET /api/engines/production' : 'Registry entry'}
              accent={healthAccent}
              icon={isProduction(engineId) ? '●' : '○'}
            />
          </div>
        </motion.section>

        {/* ── Run configuration ─────────────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/[0.08] p-6 space-y-5"
        >
          <h2 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('engines.detail_run_config')}</h2>

          {/* Client */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">Client</label>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              disabled={running}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
            >
              <option value="">{t('engines.select_client')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>

          {/* Target */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
              {t('engines.detail_target_optional')}
            </label>
            <input type="text" value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder={engine.requiresTarget ? 'https://target.com' : 'Optional — uses client scope'}
              disabled={running}
              className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50" />
          </div>

          {/* Timeout */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">{t('engines.detail_timeout')}</label>
            <input type="number" value={timeoutSec} onChange={(e) => setTimeoutSec(Number(e.target.value))}
              min={10} max={3600} disabled={running}
              className="w-36 bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono focus:outline-none focus:border-cyan-500/40 disabled:opacity-50" />
          </div>

          {/* Dynamic engine parameters */}
          {extraParamDefs.length > 0 && (
            <EngineScanParamsPanel
              engineId={engineId}
              schema={extraParamDefs}
              values={extraParams}
              onChange={setExtraParam}
              clientId={selectedClientId}
              disabled={running}
            />
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              onClick={handleRun}
              disabled={running || !engineRunnable}
              title={!engineRunnable ? t('engines.catalog_only_run_disabled') : undefined}
              className="px-5 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {running ? t('engines.running') : `▶ ${t('engines.run_engine')}`}
            </button>
            {running && (
              <button
                type="button"
                onClick={handleStop}
                className="px-4 py-2 rounded-xl font-mono text-sm border border-red-500/30 text-red-300 hover:bg-red-950/30 transition-all"
              >
                ⏹ {t('engines.stop')}
              </button>
            )}
            {lines.length > 0 && !running && (
              <button type="button" onClick={() => { setLines([]); resetFindings(); setLastRunStatus(null) }}
                className="px-3 py-2 rounded-xl font-mono text-xs border border-white/10 text-white/30 hover:text-white/60 transition-all">
                {t('engines.detail_clear')}
              </button>
            )}
          </div>
        </motion.section>

        {/* ── Output / Findings / History tabs ─────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden"
        >
          <div className="flex border-b border-white/10">
            {[
              { id:'output',   label: t('engines.live_output'),  badge: lines.length > 0 ? lines.length : null },
              { id:'findings', label: t('engines.findings_tab'), badge: findings.length > 0 ? findings.length : null },
              { id:'history',  label: t('engines.run_history'),  badge: runHistory.length > 0 ? runHistory.length : null },
            ].map((tab) => (
              <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-[11px] font-mono uppercase tracking-widest transition-colors flex items-center gap-2 ${
                  activeTab === tab.id ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-500/5' : 'text-white/40 hover:text-white/60'
                }`}>
                {tab.label}
                {tab.badge !== null && (
                  <span className={`px-1.5 py-0.5 rounded text-[9px] ${tab.id === 'findings' ? 'bg-amber-500/20 text-amber-300' : 'bg-white/10 text-white/40'}`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
          <div className="p-5">
            {activeTab === 'output'   && <Terminal lines={lines} />}
            {activeTab === 'findings' && (
              findings.length > 0
                ? (
                  <WeissmanFindingsPanel
                    findings={findings}
                    filteredFindings={filteredSessionFindings}
                    counts={findingCounts}
                    total={findings.length}
                    searchQuery={searchQuery}
                    onSearchChange={setSearchQuery}
                    severityFilter={severityFilter}
                    onSeverityChange={setSeverityFilter}
                    accent={groupDef?.color ?? '#22d3ee'}
                    title={t('engines.findings_tab')}
                    renderFinding={(f, i) => (
                      <div key={i} className="rounded-lg bg-black/40 border border-white/10 p-3 space-y-1">
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-sm font-semibold text-white/90">{f.title || f.type || 'Finding'}</span>
                          <FindingBadge severity={f.severity} />
                        </div>
                        {f.description && <p className="text-[11px] text-white/55 font-mono leading-relaxed">{f.description}</p>}
                      </div>
                    )}
                  />
                )
                : <p className="text-[11px] font-mono text-white/25">{t('engines.detail_no_findings')}</p>
            )}
            {activeTab === 'history'  && <RunHistoryPanel engineId={engineId} emptyLabel={t('engines.detail_no_history')} />}
          </div>
        </motion.section>

        {/* ── Metadata + API reference ──────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.14 }}
          className="grid grid-cols-1 sm:grid-cols-2 gap-4"
        >
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest">{t('engines.detail_metadata')}</h3>
            <table className="w-full text-[12px] font-mono">
              <tbody className="divide-y divide-white/5">
                {[
                  ['ID', engine.id],
                  ['Group', groupDef?.label || engine.group || '—'],
                  ['Type', `${engineTypeMeta.icon} ${engineTypeMeta.label}`],
                  ['MITRE', engine.mitre || '—'],
                  ['Requires Target', engine.requiresTarget ? 'Yes' : 'Optional'],
                  ['Parameters', extraParamDefs.length > 0 ? `${extraParamDefs.length} configurable` : 'Standard only'],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td className="py-1.5 pr-4 text-white/35 w-40">{k}</td>
                    <td className="py-1.5 text-white/75">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest">{t('engines.detail_api_ref')}</h3>
            <p className="text-[10px] font-mono text-white/30">Trigger via REST API:</p>
            <pre className="text-[10px] font-mono text-cyan-300/80 bg-black/50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap border border-white/5">{`POST /api/command-center/scan
{
  "engine": "${engine.id}",
  "client_id": 1,
  "target": "https://target.com"${extraParamDefs.length > 0 ? '\n  // + engine params above' : ''}
}`}</pre>
            <p className="text-[10px] font-mono text-white/30 mt-2">Stream output:</p>
            <pre className="text-[10px] font-mono text-cyan-300/80 bg-black/50 rounded-lg p-2 overflow-x-auto border border-white/5">{`GET /api/telemetry/stream?job_id={id}`}</pre>
          </div>
        </motion.section>

        </AgentRequiredGate>
      </main>
    </div>
  )
}
