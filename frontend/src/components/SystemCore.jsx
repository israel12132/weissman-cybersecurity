/**
 * System Core — God Mode controls. Cryptography & Chain of Custody.
 * Saves to system_configs (GET/POST /api/system/configs). No mock data.
 */
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { apiFetch } from '../utils/apiFetch'
import { isHttpUrl } from '../utils/safeUrl'
import AppShell from './layout/AppShell'
import LabForensicEvidence from './ui/LabForensicEvidence'
import Button from './ui/Button'

export default function SystemCore() {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [rfc3161Enabled, setRfc3161Enabled] = useState(true)
  const [x509CertPath, setX509CertPath] = useState('')
  // Ghost Network & WAF Evasion (Module 2)
  const [jitterMinMs, setJitterMinMs] = useState(0)
  const [jitterMaxMs, setJitterMaxMs] = useState(800)
  const [jitterSlider, setJitterSlider] = useState(32) // 0–100: 0 = aggressive, 100 = 500–2500 ms
  const [proxySwarm, setProxySwarm] = useState('')
  const [identityMorphing, setIdentityMorphing] = useState(true)
  // Module 4: Semantic Logic Engine (OpenAI-compatible / vLLM)
  const [llmBaseUrl, setLlmBaseUrl] = useState('')
  const [llmModel, setLlmModel] = useState('')
  const [llmTemperature, setLlmTemperature] = useState(0.7)
  const [maxSequenceDepth, setMaxSequenceDepth] = useState(8)
  // Module 5: Timing Profiler
  const [timingSampleSize, setTimingSampleSize] = useState(100)
  const [zScoreSensitivity, setZScoreSensitivity] = useState(3.0)
  // Module 6: AI Red Team
  const [aiRedteamEndpoint, setAiRedteamEndpoint] = useState('')
  const [adversarialStrategy, setAdversarialStrategy] = useState('data_leak')
  // Module 7: Zero-Day Radar
  const [enableZeroDayProbing, setEnableZeroDayProbing] = useState(true)
  const [customFeedUrls, setCustomFeedUrls] = useState('')
  // Module 8: CI/CD Integrations
  const [githubToken, setGithubToken] = useState('')
  const [gitlabApiUrl, setGitlabApiUrl] = useState('')
  // Tenant OAST (blind SSRF/XSS correlation)
  const [oastListenerUrl, setOastListenerUrl] = useState('')
  const [oastDomain, setOastDomain] = useState('')
  const [oastApiKey, setOastApiKey] = useState('')
  const [oastTestResult, setOastTestResult] = useState(null)
  const [oastTesting, setOastTesting] = useState(false)
  // AI-heavy entitlement (48 engines)
  const [aiHeavyEntitled, setAiHeavyEntitled] = useState(true)
  // Module 9: PoE Synthesis Safety Rails
  const [enablePoeSynthesis, setEnablePoeSynthesis] = useState(true)
  const [safetyRailsNoShells, setSafetyRailsNoShells] = useState(true)
  const [poeMaxPocLength, setPoeMaxPocLength] = useState(1048576)
  const [poeGadgetChains, setPoeGadgetChains] = useState('{}')
  // Threat Intelligence Feed (Autonomous Payload Sync)
  const [payloadSyncActive, setPayloadSyncActive] = useState(true)
  const [payloadSyncLastAt, setPayloadSyncLastAt] = useState('')
  const [payloadSyncRunning, setPayloadSyncRunning] = useState(false)
  const [livePayloadsCount, setLivePayloadsCount] = useState(0)
  const [activeEphemeralCount, setActiveEphemeralCount] = useState(0)
  const [recentPayloads, setRecentPayloads] = useState([])

  useEffect(() => {
    apiFetch(`/api/system/configs`)
      .then((list) => {
        const enableVal = list?.find((c) => c.key === 'enable_rfc3161_signing')?.value ?? 'true'
        setRfc3161Enabled(enableVal === 'true' || enableVal === '1')
        const certVal = list?.find((c) => c.key === 'x509_cert_path')?.value ?? ''
        setX509CertPath(certVal || '')
        const jmin = parseInt(list?.find((c) => c.key === 'jitter_min_ms')?.value ?? '0', 10) || 0
        const jmax = parseInt(list?.find((c) => c.key === 'jitter_max_ms')?.value ?? '800', 10) || 800
        setJitterMinMs(jmin)
        setJitterMaxMs(jmax)
        setProxySwarm(list?.find((c) => c.key === 'proxy_swarm')?.value ?? '')
        const morphVal = list?.find((c) => c.key === 'enable_identity_morphing')?.value ?? 'true'
        setIdentityMorphing(morphVal === 'true' || morphVal === '1')
        if (jmax <= 0) setJitterSlider(0)
        else setJitterSlider(Math.round(Math.min(100, (jmax / 2500) * 100)))
        const base =
          list?.find((c) => c.key === 'llm_base_url')?.value
          ?? list?.find((c) => c.key === 'ollama_base_url')?.value
          ?? ''
        setLlmBaseUrl((base && String(base).trim()) || '')
        setLlmModel(list?.find((c) => c.key === 'llm_model')?.value ?? '')
        const temp =
          parseFloat(
            list?.find((c) => c.key === 'llm_temperature')?.value
              ?? list?.find((c) => c.key === 'ollama_temperature')?.value
              ?? '0.7',
          ) || 0.7
        setLlmTemperature(temp)
        const depth = parseInt(list?.find((c) => c.key === 'max_sequence_depth')?.value ?? '8', 10) || 8
        setMaxSequenceDepth(depth)
        const tsize = parseInt(list?.find((c) => c.key === 'timing_sample_size')?.value ?? '100', 10) || 100
        setTimingSampleSize(Math.max(50, Math.min(500, tsize)))
        const zsc = parseFloat(list?.find((c) => c.key === 'z_score_sensitivity')?.value ?? '3.0') || 3.0
        setZScoreSensitivity(Math.max(2, Math.min(5, zsc)))
        setAiRedteamEndpoint(list?.find((c) => c.key === 'ai_redteam_endpoint')?.value ?? '')
        setAdversarialStrategy(list?.find((c) => c.key === 'adversarial_strategy')?.value ?? 'data_leak')
        setEnableZeroDayProbing((list?.find((c) => c.key === 'enable_zero_day_probing')?.value ?? 'true') === 'true')
        try {
          const urls = list?.find((c) => c.key === 'custom_feed_urls')?.value ?? '[]'
          const arr = typeof urls === 'string' ? JSON.parse(urls) : urls
          setCustomFeedUrls(Array.isArray(arr) ? arr.join('\n') : '')
        } catch (_) {
          setCustomFeedUrls('')
        }
        setGithubToken(list?.find((c) => c.key === 'github_token')?.value ?? '')
        setGitlabApiUrl(list?.find((c) => c.key === 'gitlab_api_url')?.value ?? '')
        const oastListener = list?.find((c) => c.key === 'oast_listener_url')?.value ?? ''
        setOastListenerUrl(oastListener && oastListener !== '••••••••' ? oastListener : '')
        setOastDomain(list?.find((c) => c.key === 'oast_domain')?.value ?? '')
        const oastKey = list?.find((c) => c.key === 'oast_api_key')?.value ?? ''
        setOastApiKey(oastKey === '••••••••' ? '••••••••' : oastKey)
        const aiEnt = list?.find((c) => c.key === 'ai_heavy_entitled')?.value ?? 'true'
        setAiHeavyEntitled(aiEnt !== 'false' && aiEnt !== '0')
        setEnablePoeSynthesis((list?.find((c) => c.key === 'enable_poe_synthesis')?.value ?? 'true') === 'true')
        setSafetyRailsNoShells((list?.find((c) => c.key === 'poe_safety_rails_no_shells')?.value ?? 'true') === 'true')
        setPoeMaxPocLength(Math.max(0, parseInt(list?.find((c) => c.key === 'poe_max_poc_length')?.value ?? '1048576', 10) ?? 1048576))
        const chains = list?.find((c) => c.key === 'poe_gadget_chains')?.value ?? '{}'
        try {
          setPoeGadgetChains(typeof chains === 'string' ? JSON.stringify(JSON.parse(chains), null, 2) : '{}')
        } catch (_) {
          /* invalid stored JSON; ignore and keep default */
        }
        // Threat Intel Feed status and payloads
        apiFetch(`/api/payload-sync/status`)
          .then((data) => {
            setPayloadSyncActive(!!data?.auto_sync_active)
            setPayloadSyncLastAt(data?.last_synced ?? '')
            setLivePayloadsCount(data?.live_payloads_count ?? 0)
            setActiveEphemeralCount(data?.active_ephemeral_count ?? 0)
          })
          // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
          .catch(() => {})
        apiFetch(`/api/payload-sync/payloads`)
          .then((data) => setRecentPayloads(Array.isArray(data?.payloads) ? data.payloads : []))
          // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
          .catch(() => {})
      })
      .catch(() => setError(t('components.systemCore.load_failed')))
      .finally(() => setLoading(false))
  }, [t])

  function saveConfig(key, value) {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: { configs: { [key]: value } },
    })
      .then(() => setSaving(false))
      .catch(() => {
        setError(t('components.systemCore.save_failed'))
        setSaving(false)
      })
  }

  function handleRfc3161Toggle(enabled) {
    setRfc3161Enabled(enabled)
    saveConfig('enable_rfc3161_signing', enabled ? 'true' : 'false')
  }

  function handleCertPathBlur() {
    saveConfig('x509_cert_path', x509CertPath.trim())
  }

  function saveGhostConfig() {
    setSaving(true)
    setError('')
    const minMs = jitterSlider === 0 ? 0 : Math.round((jitterSlider / 100) * 500)
    const maxMs = jitterSlider === 0 ? 0 : Math.round((jitterSlider / 100) * 2500)
    Promise.all([
      apiFetch(`/api/system/configs`, {
        method: 'POST',
        credentials: 'include',
        body: { configs: { jitter_min_ms: String(minMs), jitter_max_ms: String(maxMs), proxy_swarm: proxySwarm.trim(), enable_identity_morphing: identityMorphing ? 'true' : 'false' } },
      }),
    ])
      .then(() => { setJitterMinMs(minMs); setJitterMaxMs(maxMs); setSaving(false) })
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  function handleJitterSlider(v) {
    const val = Math.max(0, Math.min(100, Number(v)))
    setJitterSlider(val)
    const minMs = val === 0 ? 0 : Math.round((val / 100) * 500)
    const maxMs = val === 0 ? 0 : Math.round((val / 100) * 2500)
    setJitterMinMs(minMs)
    setJitterMaxMs(maxMs)
  }

  function handleIdentityMorphingToggle(enabled) {
    setIdentityMorphing(enabled)
    saveConfig('enable_identity_morphing', enabled ? 'true' : 'false')
  }

  function handleProxySwarmBlur() {
    saveConfig('proxy_swarm', proxySwarm.trim())
  }

  function saveCicdConfig() {
    setSaving(true)
    setError('')
    const gh = githubToken.trim()
    const configs = { gitlab_api_url: gitlabApiUrl.trim() }
    if (gh && gh !== '••••••••') configs.github_token = gh
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: { configs },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  function saveZeroDayConfig() {
    setSaving(true)
    setError('')
    const urls = customFeedUrls.trim().split(/\n/).map((u) => u.trim()).filter(Boolean)
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: {
        configs: {
          enable_zero_day_probing: enableZeroDayProbing ? 'true' : 'false',
          custom_feed_urls: JSON.stringify(urls),
        },
      },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  function handleZeroDayToggle(enabled) {
    setEnableZeroDayProbing(enabled)
    saveConfig('enable_zero_day_probing', enabled ? 'true' : 'false')
  }

  function saveAiRedteamConfig() {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: {
        configs: {
          ai_redteam_endpoint: aiRedteamEndpoint.trim(),
          adversarial_strategy: adversarialStrategy,
        },
      },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  function saveOastConfig() {
    setSaving(true)
    setError('')
    const configs = {
      oast_listener_url: oastListenerUrl.trim(),
      oast_domain: oastDomain.trim(),
    }
    const key = oastApiKey.trim()
    if (key && key !== '••••••••') configs.oast_api_key = key
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: { configs },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  async function testOastConnection() {
    setOastTesting(true)
    setOastTestResult(null)
    try {
      const body = { listener_url: oastListenerUrl.trim() }
      const k = oastApiKey.trim()
      if (k && k !== '••••••••') body.api_key = k
      const d = await apiFetch('/api/onboarding/oast-test', {
        method: 'POST',
        body,
      })
      setOastTestResult({ ok: true, msg: d.url || 'OK' })
    } catch (e) {
      if (e?.response) {
        const d = await e.response.json().catch(() => ({}))
        setOastTestResult({ ok: false, msg: d.detail || `HTTP ${e.status}` })
      } else {
        setOastTestResult({ ok: false, msg: e.message })
      }
    } finally {
      setOastTesting(false)
    }
  }

  function handleAiEntitlementToggle(enabled) {
    setAiHeavyEntitled(enabled)
    saveConfig('ai_heavy_entitled', enabled ? 'true' : 'false')
  }

  function saveTimingConfig() {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: {
        configs: {
          timing_sample_size: String(timingSampleSize),
          z_score_sensitivity: String(Number(zScoreSensitivity.toFixed(1))),
        },
      },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  function saveSemanticConfig() {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      body: {
        configs: {
          llm_base_url: llmBaseUrl.trim(),
          llm_model: llmModel.trim(),
          llm_temperature: String(Number(llmTemperature.toFixed(2))),
          max_sequence_depth: String(maxSequenceDepth),
        },
      },
    })
      .then(() => setSaving(false))
      .catch(() => { setError(t('components.systemCore.save_failed')); setSaving(false) })
  }

  if (loading) {
    return (
      <AppShell title={t('components.systemCore.title')}>
        <p className="text-cyan-400" role="status">{t('components.systemCore.loading')}</p>
      </AppShell>
    )
  }

  return (
    <AppShell title={t('components.systemCore.title')}>
      <LabForensicEvidence />
      <div className="mb-4 rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-[12px] text-cyan-100/90">
        {t('components.systemCore.ownership_banner')}{' '}
        <Link to="/system-config" className="underline text-cyan-300">{t('nav.system_config')}</Link>
        {' · '}
        <Link to="/settings/integrations" className="underline text-cyan-300">{t('nav.integrations')}</Link>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}
      {saving && (
        <p className="mb-2 text-amber-400 text-sm">{t('components.systemCore.saving')}</p>
      )}

      <section className="max-w-2xl rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.crypto_heading')}</h2>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.rfc3161_label')}</label>
            <Button variant="unstyled"
              type="button"
              role="switch"
              aria-checked={rfc3161Enabled}
              onClick={() => handleRfc3161Toggle(!rfc3161Enabled)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${rfc3161Enabled ? 'bg-cyan-500/80 border-cyan-400' : 'bg-[var(--bg-4)] border-[var(--border-strong)]'}`}
            >
              <span
                className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${rfc3161Enabled ? 'translate-x-6' : 'translate-x-1'}`}
              />
            </Button>
          </div>

          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.x509_label')}</label>
            <input
              type="text"
              value={x509CertPath}
              onChange={(e) => setX509CertPath(e.target.value)}
              onBlur={handleCertPathBlur}
              placeholder={t('components.systemCore.x509_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
        </div>

        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.crypto_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.ghost_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.ghost_body')}
        </p>

        <div className="space-y-6">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">
              {t('components.systemCore.jitter_label')}
            </label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-[var(--text-muted)] w-24">{t('components.systemCore.jitter_aggressive')}</span>
              <input
                type="range"
                min={0}
                max={100}
                value={jitterSlider}
                onChange={(e) => handleJitterSlider(e.target.value)}
                className="flex-1 h-2 rounded-full appearance-none bg-[var(--bg-4)] accent-cyan-500"
              />
              <span className="text-xs text-[var(--text-muted)] w-28">{t('components.systemCore.jitter_stealth')}</span>
            </div>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              {t('components.systemCore.jitter_current', { min: jitterMinMs, max: jitterMaxMs })}
            </p>
          </div>

          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.proxy_label')}</label>
            <textarea
              value={proxySwarm}
              onChange={(e) => setProxySwarm(e.target.value)}
              onBlur={handleProxySwarmBlur}
              placeholder={t('components.systemCore.proxy_placeholder')}
              rows={4}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono text-sm"
            />
          </div>

          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.morphing_label')}</label>
            <Button variant="unstyled"
              type="button"
              role="switch"
              aria-checked={identityMorphing}
              onClick={() => handleIdentityMorphingToggle(!identityMorphing)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${identityMorphing ? 'bg-cyan-500/80 border-cyan-400' : 'bg-[var(--bg-4)] border-[var(--border-strong)]'}`}
            >
              <span
                className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${identityMorphing ? 'translate-x-6' : 'translate-x-1'}`}
              />
            </Button>
          </div>

          <Button variant="unstyled"
            type="button"
            onClick={saveGhostConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_ghost')}
          </Button>
        </div>

        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.ghost_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.semantic_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.semantic_body')}
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.llm_url_label')}</label>
            <input
              type="text"
              value={llmBaseUrl}
              onChange={(e) => setLlmBaseUrl(e.target.value)}
              placeholder={t('components.systemCore.llm_url_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.llm_model_label')}</label>
            <input
              type="text"
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              placeholder={t('components.systemCore.llm_model_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.llm_temp_label')}</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-[var(--text-muted)] w-12">0.0</span>
              <input
                type="range"
                min={0}
                max={200}
                value={Math.round(llmTemperature * 100)}
                onChange={(e) => setLlmTemperature(Number(e.target.value) / 100)}
                className="flex-1 h-2 rounded-full appearance-none bg-[var(--bg-4)] accent-cyan-500"
              />
              <span className="text-xs text-[var(--text-muted)] w-12">2.0</span>
            </div>
            <p className="mt-1 text-xs text-[var(--text-muted)]">{t('components.systemCore.llm_temp_current', { value: llmTemperature.toFixed(2) })}</p>
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.max_depth_label')}</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-[var(--text-muted)]">1</span>
              <input
                type="range"
                min={1}
                max={20}
                value={maxSequenceDepth}
                onChange={(e) => setMaxSequenceDepth(Number(e.target.value))}
                className="flex-1 h-2 rounded-full appearance-none bg-[var(--bg-4)] accent-cyan-500"
              />
              <span className="text-xs text-[var(--text-muted)]">20</span>
            </div>
            <p className="mt-1 text-xs text-[var(--text-muted)]">{t('components.systemCore.max_depth_current', { value: maxSequenceDepth })}</p>
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={saveSemanticConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_semantic')}
          </Button>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.semantic_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-violet-600/40 bg-violet-950/20 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-violet-200 mb-4">{t('components.systemCore.oast_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.oast_body')}
        </p>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.oast_listener_label')}</label>
            <input type="url" value={oastListenerUrl} onChange={(e) => setOastListenerUrl(e.target.value)}
              placeholder="https://oast.your-domain.example:9090"
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)]" />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.oast_domain_label')}</label>
            <input type="text" value={oastDomain} onChange={(e) => setOastDomain(e.target.value)}
              placeholder="oast.your-domain.example"
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)]" />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.oast_api_key_label')}</label>
            <input type="password" autoComplete="off" value={oastApiKey} onChange={(e) => setOastApiKey(e.target.value)}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)]" />
          </div>
          <div className="flex flex-wrap gap-3">
            <Button variant="unstyled" type="button" onClick={saveOastConfig} disabled={saving}
              className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-sm font-medium">
              {saving ? t('components.systemCore.saving') : t('components.systemCore.save_oast')}
            </Button>
            <Button variant="unstyled" type="button" onClick={testOastConnection} disabled={oastTesting || !oastListenerUrl.trim()}
              className="px-4 py-2 rounded-lg border border-violet-500/40 text-violet-200 text-sm hover:bg-violet-500/10 disabled:opacity-50">
              {oastTesting ? t('components.systemCore.oast_testing') : t('components.systemCore.oast_test')}
            </Button>
            <Link to="/oast" className="px-4 py-2 text-sm text-violet-300 hover:text-violet-200 self-center">
              {t('components.systemCore.oast_dashboard')}
            </Link>
          </div>
          {oastTestResult && (
            <p className={`text-xs ${oastTestResult.ok ? 'text-emerald-400' : 'text-rose-400'}`}>
              {oastTestResult.ok ? `✓ ${oastTestResult.msg}` : oastTestResult.msg}
            </p>
          )}
        </div>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-pink-600/30 bg-pink-950/15 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-pink-200 mb-4">{t('components.systemCore.ai_entitlement_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-4">
          {t('components.systemCore.ai_entitlement_body')}
        </p>
        <div className="flex items-center justify-between">
          <span className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.ai_entitlement_label')}</span>
          <Button variant="unstyled" type="button" role="switch" aria-checked={aiHeavyEntitled}
            onClick={() => handleAiEntitlementToggle(!aiHeavyEntitled)}
            className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${aiHeavyEntitled ? 'bg-pink-500/80 border-pink-400' : 'bg-[var(--bg-4)] border-[var(--border-strong)]'}`}>
            <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow transition ${aiHeavyEntitled ? 'translate-x-6' : 'translate-x-1'}`} />
          </Button>
        </div>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.timing_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.timing_body')}
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.timing_sample_label')}</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-[var(--text-muted)] w-10">50</span>
              <input
                type="range"
                min={50}
                max={500}
                value={timingSampleSize}
                onChange={(e) => setTimingSampleSize(Number(e.target.value))}
                className="flex-1 h-2 rounded-full appearance-none bg-[var(--bg-4)] accent-cyan-500"
              />
              <span className="text-xs text-[var(--text-muted)] w-10">500</span>
            </div>
            <p className="mt-1 text-xs text-[var(--text-muted)]">{t('components.systemCore.timing_sample_current', { value: timingSampleSize })}</p>
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.zscore_label')}</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-[var(--text-muted)] w-10">2.0</span>
              <input
                type="range"
                min={20}
                max={50}
                value={Math.round(zScoreSensitivity * 10)}
                onChange={(e) => setZScoreSensitivity(Number(e.target.value) / 10)}
                className="flex-1 h-2 rounded-full appearance-none bg-[var(--bg-4)] accent-cyan-500"
              />
              <span className="text-xs text-[var(--text-muted)] w-10">5.0</span>
            </div>
            <p className="mt-1 text-xs text-[var(--text-muted)]">{t('components.systemCore.zscore_current', { value: zScoreSensitivity.toFixed(1), current: zScoreSensitivity.toFixed(1) })}</p>
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={saveTimingConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_timing')}
          </Button>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.timing_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.redteam_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.redteam_body')}
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.redteam_endpoint_label')}</label>
            <input
              type="text"
              value={aiRedteamEndpoint}
              onChange={(e) => setAiRedteamEndpoint(e.target.value)}
              placeholder={t('components.systemCore.redteam_endpoint_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.redteam_strategy_label')}</label>
            <select
              value={adversarialStrategy}
              onChange={(e) => setAdversarialStrategy(e.target.value)}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="data_leak">{t('components.systemCore.strategy_data_leak')}</option>
              <option value="code_execution">{t('components.systemCore.strategy_code_exec')}</option>
            </select>
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={saveAiRedteamConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_redteam')}
          </Button>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.redteam_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.zeroday_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.zeroday_body')}
        </p>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.zeroday_enable')}</label>
            <Button variant="unstyled"
              type="button"
              role="switch"
              aria-checked={enableZeroDayProbing}
              onClick={() => handleZeroDayToggle(!enableZeroDayProbing)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${enableZeroDayProbing ? 'bg-cyan-500/80 border-cyan-400' : 'bg-[var(--bg-4)] border-[var(--border-strong)]'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${enableZeroDayProbing ? 'translate-x-6' : 'translate-x-1'}`} />
            </Button>
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.feed_urls_label')}</label>
            <textarea
              value={customFeedUrls}
              onChange={(e) => setCustomFeedUrls(e.target.value)}
              placeholder={t('components.systemCore.feed_urls_placeholder')}
              rows={3}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)] font-mono text-sm"
            />
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={saveZeroDayConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_zeroday')}
          </Button>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.zeroday_hint')}
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.cicd_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.cicd_body')}
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.github_token_label')}</label>
            <input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder={t('components.systemCore.github_token_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)]"
              autoComplete="off"
            />
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.gitlab_url_label')}</label>
            <input
              type="text"
              value={gitlabApiUrl}
              onChange={(e) => setGitlabApiUrl(e.target.value)}
              placeholder={t('components.systemCore.gitlab_url_placeholder')}
              className="w-full rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] placeholder-[var(--text-muted)]"
            />
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={saveCicdConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? t('components.systemCore.saving') : t('components.systemCore.save_cicd')}
          </Button>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.cicd_hint')}
        </p>
      </section>

      <section className="rounded-xl border border-[var(--border-default)]/60 bg-[var(--bg-1)]/40 p-6 mb-6">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t('components.systemCore.poe_heading')}</h2>
        <p className="text-sm text-[var(--text-tertiary)] mb-6">
          {t('components.systemCore.poe_body')}
        </p>
        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <Button variant="unstyled"
              type="button"
              role="switch"
              aria-checked={enablePoeSynthesis}
              onClick={() => {
                setEnablePoeSynthesis(!enablePoeSynthesis)
                saveConfig('enable_poe_synthesis', !enablePoeSynthesis ? 'true' : 'false')
              }}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${enablePoeSynthesis ? 'bg-emerald-600' : 'bg-[var(--bg-4)]'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition translate-x-1 translate-y-0.5 ${enablePoeSynthesis ? 'translate-x-6' : 'translate-x-1'}`} />
            </Button>
            <span className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.poe_enable')}</span>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="unstyled"
              type="button"
              role="switch"
              aria-checked={safetyRailsNoShells}
              onClick={() => {
                setSafetyRailsNoShells(!safetyRailsNoShells)
                saveConfig('poe_safety_rails_no_shells', !safetyRailsNoShells ? 'true' : 'false')
              }}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${safetyRailsNoShells ? 'bg-emerald-600' : 'bg-[var(--bg-4)]'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition translate-x-1 translate-y-0.5 ${safetyRailsNoShells ? 'translate-x-6' : 'translate-x-1'}`} />
            </Button>
            <span className="text-sm text-[var(--text-secondary)]">{t('components.systemCore.poe_no_shells')}</span>
          </div>
          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.poe_max_length')}</label>
            <input
              type="number"
              min={0}
              value={poeMaxPocLength}
              onChange={(e) => { const n = parseInt(e.target.value, 10); setPoeMaxPocLength(Number.isNaN(n) ? 0 : Math.max(0, n)) }}
              onBlur={() => saveConfig('poe_max_poc_length', String(poeMaxPocLength))}
              className="w-36 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)]"
            />
          </div>

          <div className="rounded-lg border border-[var(--border-strong)]/80 bg-[var(--bg-3)]/40 p-4">
            <h3 className="text-sm font-semibold text-[var(--text-secondary)] mb-3">{t('components.systemCore.threat_feed_heading')}</h3>
            <div className="flex flex-wrap items-center gap-4 mb-3">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${payloadSyncActive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-[var(--bg-4)]/40 text-[var(--text-tertiary)]'}`}>
                <span className={`w-2 h-2 rounded-full ${payloadSyncActive ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--border-strong)]'}`} />
                {t('components.systemCore.auto_sync_active')}
              </span>
              <span className="text-xs text-[var(--text-tertiary)]">
                {t('components.systemCore.last_synced', { value: payloadSyncLastAt ? new Date(payloadSyncLastAt).toLocaleString() : t('components.systemCore.last_synced_never') })}
              </span>
              <span className="text-xs text-[var(--text-secondary)] font-mono">
                {t('components.systemCore.live_payloads', { count: livePayloadsCount })}
              </span>
              <span className="text-xs text-[var(--text-secondary)] font-mono">
                {t('components.systemCore.ephemeral_payloads', { count: activeEphemeralCount })}
              </span>
              <Button variant="unstyled"
                type="button"
                disabled={payloadSyncRunning}
                onClick={async () => {
                  setPayloadSyncRunning(true)
                  try {
                    await apiFetch(`/api/payload-sync/run`, { method: 'POST' })
                    setError('')
                  } catch {
                    setError(t('components.systemCore.sync_failed'))
                  } finally {
                    setPayloadSyncRunning(false)
                    const st = await apiFetch(`/api/payload-sync/status`).catch(() => ({}))
                    if (st.last_synced) setPayloadSyncLastAt(st.last_synced)
                    if (typeof st.live_payloads_count === 'number') setLivePayloadsCount(st.live_payloads_count)
                    if (typeof st.active_ephemeral_count === 'number') setActiveEphemeralCount(st.active_ephemeral_count)
                    const pl = await apiFetch(`/api/payload-sync/payloads`).catch(() => ({ payloads: [] }))
                    if (Array.isArray(pl.payloads)) setRecentPayloads(pl.payloads)
                  }
                }}
                className="ml-auto px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium"
              >
                {payloadSyncRunning ? t('components.systemCore.syncing') : t('components.systemCore.sync_now')}
              </Button>
            </div>
            <p className="text-xs text-[var(--text-muted)] mb-2">{t('components.systemCore.payloads_hint')}</p>
            <p className="text-xs text-[var(--text-muted)] mb-2">
              {t('components.systemCore.engine_hint')}
            </p>
            <div className="max-h-48 overflow-y-auto rounded border border-[var(--border-strong)]/60 bg-[var(--bg-1)]/60 divide-y divide-[var(--border-default)]/60">
              {recentPayloads.length === 0 ? (
                <div className="py-4 px-3 text-xs text-[var(--text-muted)] text-center">{t('components.systemCore.no_payloads')}</div>
              ) : (
                recentPayloads.map((p) => (
                  <div key={p.id} className="py-2 px-3 text-left">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-amber-400">{p.target_library}</span>
                      <span className="text-xs text-[var(--text-muted)]">{p.source}</span>
                      <span className="text-xs text-[var(--text-muted)]">{p.added_at ? new Date(p.added_at).toLocaleString() : ''}</span>
                    </div>
                    {p.source_url && (
                      isHttpUrl(p.source_url) ? (
                        <a
                          href={p.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="block mt-0.5 text-xs text-cyan-400 hover:text-cyan-300 truncate max-w-full"
                          title={p.source_url}
                        >
                          {p.source_url}
                        </a>
                      ) : (
                        <span className="block mt-0.5 text-xs text-[var(--text-muted)] truncate max-w-full" title={p.source_url}>{p.source_url}</span>
                      )
                    )}
                    <pre className="mt-1 text-xs text-[var(--text-tertiary)] truncate max-w-full overflow-hidden" title={p.payload_preview}>
                      {typeof p.payload_preview === 'string' ? p.payload_preview.slice(0, 120) + (p.payload_preview.length > 120 ? '…' : '') : ''}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>

          <div>
            <label className="block text-sm text-[var(--text-secondary)] mb-2">{t('components.systemCore.gadget_chains_label')}</label>
            <p className="text-xs text-[var(--text-muted)] mb-2">{t('components.systemCore.gadget_chains_hint')}</p>
            <textarea
              value={poeGadgetChains}
              onChange={(e) => setPoeGadgetChains(e.target.value)}
              onBlur={() => {
                try {
                  const parsed = JSON.parse(poeGadgetChains)
                  if (typeof parsed === 'object' && parsed !== null) saveConfig('poe_gadget_chains', JSON.stringify(parsed))
                } catch (_) { /* invalid JSON on blur; ignore */ }
              }}
              className="w-full min-h-[120px] rounded-lg border border-[var(--border-strong)] bg-[var(--bg-3)]/80 px-3 py-2 text-[var(--text-secondary)] font-mono text-sm"
              placeholder={t('components.systemCore.gadget_chains_placeholder')}
            />
          </div>
        </div>
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          {t('components.systemCore.poe_footer')}
        </p>
      </section>
    </AppShell>
  )
}
