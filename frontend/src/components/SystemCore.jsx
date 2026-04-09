/**
 * System Core — God Mode controls. Cryptography & Chain of Custody.
 * Saves to system_configs (GET/POST /api/system/configs). No mock data.
 */
import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

export default function SystemCore() {
  const [configs, setConfigs] = useState([])
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
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Failed to load configs'))))
      .then((list) => {
        setConfigs(Array.isArray(list) ? list : [])
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
        setEnablePoeSynthesis((list?.find((c) => c.key === 'enable_poe_synthesis')?.value ?? 'true') === 'true')
        setSafetyRailsNoShells((list?.find((c) => c.key === 'poe_safety_rails_no_shells')?.value ?? 'true') === 'true')
        setPoeMaxPocLength(Math.max(0, parseInt(list?.find((c) => c.key === 'poe_max_poc_length')?.value ?? '1048576', 10) ?? 1048576))
        const chains = list?.find((c) => c.key === 'poe_gadget_chains')?.value ?? '{}'
        try {
          setPoeGadgetChains(typeof chains === 'string' ? JSON.stringify(JSON.parse(chains), null, 2) : '{}')
        } catch (_) {
        }
        // Threat Intel Feed status and payloads
        apiFetch(`/api/payload-sync/status`)
          .then((r) => (r.ok ? r.json() : Promise.reject()))
          .then((data) => {
            setPayloadSyncActive(!!data?.auto_sync_active)
            setPayloadSyncLastAt(data?.last_synced ?? '')
            setLivePayloadsCount(data?.live_payloads_count ?? 0)
            setActiveEphemeralCount(data?.active_ephemeral_count ?? 0)
          })
          .catch(() => {})
        apiFetch(`/api/payload-sync/payloads`)
          .then((r) => (r.ok ? r.json() : Promise.reject()))
          .then((data) => setRecentPayloads(Array.isArray(data?.payloads) ? data.payloads : []))
          .catch(() => {})
      })
      .catch((e) => setError(e?.message || 'Load failed'))
      .finally(() => setLoading(false))
  }, [])

  function saveConfig(key, value) {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ configs: { [key]: value } }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => {
        setError(e?.message || 'Save failed')
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
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ configs: { jitter_min_ms: String(minMs), jitter_max_ms: String(maxMs), proxy_swarm: proxySwarm.trim(), enable_identity_morphing: identityMorphing ? 'true' : 'false' } }),
      }),
    ])
      .then(([r]) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => { setJitterMinMs(minMs); setJitterMaxMs(maxMs); setSaving(false) })
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
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
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs: {
          github_token: githubToken.trim(),
          gitlab_api_url: gitlabApiUrl.trim(),
        },
      }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
  }

  function saveZeroDayConfig() {
    setSaving(true)
    setError('')
    const urls = customFeedUrls.trim().split(/\n/).map((u) => u.trim()).filter(Boolean)
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs: {
          enable_zero_day_probing: enableZeroDayProbing ? 'true' : 'false',
          custom_feed_urls: JSON.stringify(urls),
        },
      }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs: {
          ai_redteam_endpoint: aiRedteamEndpoint.trim(),
          adversarial_strategy: adversarialStrategy,
        },
      }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
  }

  function saveTimingConfig() {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs: {
          timing_sample_size: String(timingSampleSize),
          z_score_sensitivity: String(Number(zScoreSensitivity.toFixed(1))),
        },
      }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
  }

  function saveSemanticConfig() {
    setSaving(true)
    setError('')
    apiFetch(`/api/system/configs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configs: {
          llm_base_url: llmBaseUrl.trim(),
          llm_model: llmModel.trim(),
          llm_temperature: String(Number(llmTemperature.toFixed(2))),
          max_sequence_depth: String(maxSequenceDepth),
        },
      }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Save failed'))))
      .then(() => setSaving(false))
      .catch((e) => { setError(e?.message || 'Save failed'); setSaving(false) })
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <p className="text-cyan-400">Loading System Core…</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <header className="flex items-center justify-between border-b border-slate-700 pb-4 mb-6">
        <h1 className="text-xl font-bold text-cyan-400">System Core</h1>
        <Link to="/" className="text-sm text-slate-400 hover:text-cyan-400">← War Room</Link>
      </header>

      {error && (
        <div className="mb-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}
      {saving && (
        <p className="mb-2 text-amber-400 text-sm">Saving…</p>
      )}

      <section className="max-w-2xl rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Cryptography & Chain of Custody</h2>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <label className="text-sm text-slate-300">Enable RFC 3161 PDF Signing & Immutable Audit Trail</label>
            <button
              type="button"
              role="switch"
              aria-checked={rfc3161Enabled}
              onClick={() => handleRfc3161Toggle(!rfc3161Enabled)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${rfc3161Enabled ? 'bg-cyan-500/80 border-cyan-400' : 'bg-slate-600 border-slate-500'}`}
            >
              <span
                className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${rfc3161Enabled ? 'translate-x-6' : 'translate-x-1'}`}
              />
            </button>
          </div>

          <div>
            <label className="block text-sm text-slate-300 mb-2">Custom X.509 Certificate Path</label>
            <input
              type="text"
              value={x509CertPath}
              onChange={(e) => setX509CertPath(e.target.value)}
              onBlur={handleCertPathBlur}
              placeholder="Leave empty for auto-generated self-signed (data/certs)"
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
        </div>

        <p className="mt-4 text-xs text-slate-500">
          Settings are stored in system_configs and apply in real time. No restart required.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Ghost Network & WAF Evasion</h2>
        <p className="text-sm text-slate-400 mb-6">
          Distribute requests and emulate human browsing delays. Config applies to all attack engines in real time.
        </p>

        <div className="space-y-6">
          <div>
            <label className="block text-sm text-slate-300 mb-2">
              Jitter intensity (human emulation)
            </label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-500 w-24">Aggressive (0 ms)</span>
              <input
                type="range"
                min={0}
                max={100}
                value={jitterSlider}
                onChange={(e) => handleJitterSlider(e.target.value)}
                className="flex-1 h-2 rounded-full appearance-none bg-slate-600 accent-cyan-500"
              />
              <span className="text-xs text-slate-500 w-28">Stealth (500–2500 ms)</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Current: {jitterMinMs}–{jitterMaxMs} ms delay before each request
            </p>
          </div>

          <div>
            <label className="block text-sm text-slate-300 mb-2">Global proxy swarm (one proxy per line or comma-separated)</label>
            <textarea
              value={proxySwarm}
              onChange={(e) => setProxySwarm(e.target.value)}
              onBlur={handleProxySwarmBlur}
              placeholder="http://proxy1:8080, http://proxy2:3128"
              rows={4}
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono text-sm"
            />
          </div>

          <div className="flex items-center justify-between">
            <label className="text-sm text-slate-300">Enable identity morphing (browser fingerprint rotation)</label>
            <button
              type="button"
              role="switch"
              aria-checked={identityMorphing}
              onClick={() => handleIdentityMorphingToggle(!identityMorphing)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${identityMorphing ? 'bg-cyan-500/80 border-cyan-400' : 'bg-slate-600 border-slate-500'}`}
            >
              <span
                className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${identityMorphing ? 'translate-x-6' : 'translate-x-1'}`}
              />
            </button>
          </div>

          <button
            type="button"
            onClick={saveGhostConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save Ghost Network settings'}
          </button>
        </div>

        <p className="mt-4 text-xs text-slate-500">
          Jitter, proxy rotation, and morphing apply to OSINT, ASM, supply chain, BOLA/IDOR, and LLM-driven fuzzing. No restart required.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Semantic Logic Engine (Module 4)</h2>
        <p className="text-sm text-slate-400 mb-6">
          Control AI-driven business logic fuzzing: local vLLM (OpenAI-compatible) endpoint, model id, temperature, and how many API endpoints to analyze per target.
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-slate-300 mb-2">LLM base URL (OpenAI API, include /v1)</label>
            <input
              type="text"
              value={llmBaseUrl}
              onChange={(e) => setLlmBaseUrl(e.target.value)}
              placeholder="https://your-vllm-host.example/v1"
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Model id (optional if WEISSMAN_LLM_MODEL is set on server)</label>
            <input
              type="text"
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              placeholder="e.g. meta-llama/Llama-3.2-3B-Instruct"
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">LLM temperature</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-500 w-12">0.0</span>
              <input
                type="range"
                min={0}
                max={200}
                value={Math.round(llmTemperature * 100)}
                onChange={(e) => setLlmTemperature(Number(e.target.value) / 100)}
                className="flex-1 h-2 rounded-full appearance-none bg-slate-600 accent-cyan-500"
              />
              <span className="text-xs text-slate-500 w-12">2.0</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">Current: {llmTemperature.toFixed(2)} — higher = more creative payloads</p>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Max Sequence Depth</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-500">1</span>
              <input
                type="range"
                min={1}
                max={20}
                value={maxSequenceDepth}
                onChange={(e) => setMaxSequenceDepth(Number(e.target.value))}
                className="flex-1 h-2 rounded-full appearance-none bg-slate-600 accent-cyan-500"
              />
              <span className="text-xs text-slate-500">20</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">Max API endpoints to analyze per target: {maxSequenceDepth}</p>
          </div>
          <button
            type="button"
            onClick={saveSemanticConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save Semantic Logic settings'}
          </button>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Findings are saved with source <code className="bg-slate-800 px-1 rounded">semantic_ai_fuzz</code> and appear in the Executive PDF with AI remediation.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Quantum Timing Profiler (Module 5)</h2>
        <p className="text-sm text-slate-400 mb-6">
          Microsecond timing attacks: baseline sample size and Z-Score sensitivity for blind injection detection. Used by the orchestrator and the Timing Profiler UI.
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-slate-300 mb-2">Timing sample size (baseline + payload requests)</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-500 w-10">50</span>
              <input
                type="range"
                min={50}
                max={500}
                value={timingSampleSize}
                onChange={(e) => setTimingSampleSize(Number(e.target.value))}
                className="flex-1 h-2 rounded-full appearance-none bg-slate-600 accent-cyan-500"
              />
              <span className="text-xs text-slate-500 w-10">500</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">Current: {timingSampleSize} requests per phase</p>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Z-Score sensitivity (anomaly threshold)</label>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-500 w-10">2.0</span>
              <input
                type="range"
                min={20}
                max={50}
                value={Math.round(zScoreSensitivity * 10)}
                onChange={(e) => setZScoreSensitivity(Number(e.target.value) / 10)}
                className="flex-1 h-2 rounded-full appearance-none bg-slate-600 accent-cyan-500"
              />
              <span className="text-xs text-slate-500 w-10">5.0</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">Z-Score &gt; {zScoreSensitivity} = critical timing deviation. Current: {zScoreSensitivity.toFixed(1)}</p>
          </div>
          <button
            type="button"
            onClick={saveTimingConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save Timing Profiler settings'}
          </button>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Findings are saved with source <code className="bg-slate-800 px-1 rounded">microsecond_timing</code>; delta_us, z_score and payload appear in the report.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">AI Red Teaming Arena (Module 6)</h2>
        <p className="text-sm text-slate-400 mb-6">
          Target AI endpoint and adversarial strategy for LLM red teaming (OWASP LLM01). Used by the orchestrator and the AI Combat Arena.
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-slate-300 mb-2">Target AI Endpoint URL</label>
            <input
              type="text"
              value={aiRedteamEndpoint}
              onChange={(e) => setAiRedteamEndpoint(e.target.value)}
              placeholder="https://target.com/chat (empty = use client target + /chat)"
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Adversarial Strategy</label>
            <select
              value={adversarialStrategy}
              onChange={(e) => setAdversarialStrategy(e.target.value)}
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="data_leak">Data Leak (prompt extraction, jailbreaks)</option>
              <option value="code_execution">Code Execution (run commands, bypass safety)</option>
            </select>
          </div>
          <button
            type="button"
            onClick={saveAiRedteamConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save AI Red Team settings'}
          </button>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Findings saved with source <code className="bg-slate-800 px-1 rounded">ai_adversarial_redteam</code>; include AI vulnerabilities section in Executive PDF.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Zero-Day Radar (Module 7)</h2>
        <p className="text-sm text-slate-400 mb-6">
          Autonomous zero-day detection: NVD + custom feeds, Ollama-safe probe synthesis, scan client assets. Probes are detection-only (no destructive exploits).
        </p>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <label className="text-sm text-slate-300">Enable Autonomous Zero-Day Probing</label>
            <button
              type="button"
              role="switch"
              aria-checked={enableZeroDayProbing}
              onClick={() => handleZeroDayToggle(!enableZeroDayProbing)}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border transition-colors ${enableZeroDayProbing ? 'bg-cyan-500/80 border-cyan-400' : 'bg-slate-600 border-slate-500'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition ${enableZeroDayProbing ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Custom RSS / Threat Feed URLs (one per line)</label>
            <textarea
              value={customFeedUrls}
              onChange={(e) => setCustomFeedUrls(e.target.value)}
              placeholder="https://example.com/security.rss"
              rows={3}
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500 font-mono text-sm"
            />
          </div>
          <button
            type="button"
            onClick={saveZeroDayConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save Zero-Day Radar settings'}
          </button>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Findings saved with source <code className="bg-slate-800 px-1 rounded">zero_day_radar</code>; safe probe matches only.
        </p>
      </section>

      <section className="max-w-2xl mt-8 rounded-xl border border-slate-600/80 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">CI/CD Integrations (Module 8)</h2>
        <p className="text-sm text-slate-400 mb-6">
          GitHub PAT and GitLab API URL for IaC pipeline scan. Repo content is fetched dynamically; PoC is stored only, never deployed.
        </p>
        <div className="space-y-6">
          <div>
            <label className="block text-sm text-slate-300 mb-2">GitHub Personal Access Token</label>
            <input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="ghp_..."
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500"
              autoComplete="off"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">GitLab API URL</label>
            <input
              type="text"
              value={gitlabApiUrl}
              onChange={(e) => setGitlabApiUrl(e.target.value)}
              placeholder="https://gitlab.com/api/v4"
              className="w-full rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 placeholder-slate-500"
            />
          </div>
          <button
            type="button"
            onClick={saveCicdConfig}
            disabled={saving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm"
          >
            {saving ? 'Saving…' : 'Save CI/CD settings'}
          </button>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Used by Phantom Pipeline / CI/CD Matrix. PoC exploit stored in <code className="bg-slate-800 px-1 rounded">poc_exploit</code> column only.
        </p>
      </section>

      <section className="rounded-xl border border-slate-700/60 bg-slate-900/40 p-6 mb-6">
        <h2 className="text-lg font-semibold text-slate-200 mb-4">Safety Rails — Proof-of-Exploitability (Module 9)</h2>
        <p className="text-sm text-slate-400 mb-6">
          Control autonomous PoE synthesis. All payloads are SAFE (no reverse shells or malware). Only benign proof-of-concept detection.
        </p>
        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              role="switch"
              aria-checked={enablePoeSynthesis}
              onClick={() => {
                setEnablePoeSynthesis(!enablePoeSynthesis)
                saveConfig('enable_poe_synthesis', !enablePoeSynthesis ? 'true' : 'false')
              }}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${enablePoeSynthesis ? 'bg-emerald-600' : 'bg-slate-600'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition translate-x-1 translate-y-0.5 ${enablePoeSynthesis ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
            <span className="text-sm text-slate-300">Enable PoE Synthesis (crash triage + safe PoC)</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              role="switch"
              aria-checked={safetyRailsNoShells}
              onClick={() => {
                setSafetyRailsNoShells(!safetyRailsNoShells)
                saveConfig('poe_safety_rails_no_shells', !safetyRailsNoShells ? 'true' : 'false')
              }}
              className={`relative inline-flex h-7 w-12 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${safetyRailsNoShells ? 'bg-emerald-600' : 'bg-slate-600'}`}
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition translate-x-1 translate-y-0.5 ${safetyRailsNoShells ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
            <span className="text-sm text-slate-300">Never generate reverse/bind shell payloads</span>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-2">Max PoC payload length (chars; 0 = unlimited streaming)</label>
            <input
              type="number"
              min={0}
              value={poeMaxPocLength}
              onChange={(e) => setPoeMaxPocLength(Math.max(0, parseInt(e.target.value, 10) ?? 0))}
              onBlur={() => saveConfig('poe_max_poc_length', String(poeMaxPocLength))}
              className="w-36 rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200"
            />
          </div>

          <div className="rounded-lg border border-slate-600/80 bg-slate-800/40 p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Threat Intelligence Feed (Live Ammo)</h3>
            <div className="flex flex-wrap items-center gap-4 mb-3">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${payloadSyncActive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-600/40 text-slate-400'}`}>
                <span className={`w-2 h-2 rounded-full ${payloadSyncActive ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                Auto-Sync Active
              </span>
              <span className="text-xs text-slate-400">
                Last Synced: {payloadSyncLastAt ? new Date(payloadSyncLastAt).toLocaleString() : 'Never'}
              </span>
              <span className="text-xs text-slate-300 font-mono">
                Live Payloads (Last 60 Days): <strong className="text-amber-400">{livePayloadsCount}</strong>
              </span>
              <span className="text-xs text-slate-300 font-mono">
                Active Ephemeral Payloads (7-day warehouse): <strong className="text-violet-400">{activeEphemeralCount}</strong>
              </span>
              <button
                type="button"
                disabled={payloadSyncRunning}
                onClick={async () => {
                  setPayloadSyncRunning(true)
                  try {
                    const r = await apiFetch(`/api/payload-sync/run`, { method: 'POST' })
                    if (r.ok) setError('')
                    else setError('Sync request failed')
                  } finally {
                    setPayloadSyncRunning(false)
                    const st = await apiFetch(`/api/payload-sync/status`).then((res) => res.ok ? res.json() : {})
                    if (st.last_synced) setPayloadSyncLastAt(st.last_synced)
                    if (typeof st.live_payloads_count === 'number') setLivePayloadsCount(st.live_payloads_count)
                    if (typeof st.active_ephemeral_count === 'number') setActiveEphemeralCount(st.active_ephemeral_count)
                    const pl = await apiFetch(`/api/payload-sync/payloads`).then((res) => res.ok ? res.json() : { payloads: [] })
                    if (Array.isArray(pl.payloads)) setRecentPayloads(pl.payloads)
                  }
                }}
                className="ml-auto px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium"
              >
                {payloadSyncRunning ? 'Syncing…' : 'Sync Intelligence Now'}
              </button>
            </div>
            <p className="text-xs text-slate-500 mb-2">Recently fetched payloads (read-only); engine uses these before Ollama.</p>
            <p className="text-xs text-slate-500 mb-2">
              Engine: <strong className="text-slate-400">Uncapped concurrency</strong> (hardware limit) · <strong className="text-slate-400">Forensic context</strong> (smoking guns only to Ollama) · <strong className="text-slate-400">Ephemeral payloads</strong> 7-day auto-purge after first use · <strong className="text-slate-400">Global hunt</strong> (Exploit-DB/GitHub when ammo missing).
            </p>
            <div className="max-h-48 overflow-y-auto rounded border border-slate-600/60 bg-slate-900/60 divide-y divide-slate-700/60">
              {recentPayloads.length === 0 ? (
                <div className="py-4 px-3 text-xs text-slate-500 text-center">No payloads yet. Sync runs every 12h.</div>
              ) : (
                recentPayloads.map((p) => (
                  <div key={p.id} className="py-2 px-3 text-left">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-amber-400">{p.target_library}</span>
                      <span className="text-xs text-slate-500">{p.source}</span>
                      <span className="text-xs text-slate-600">{p.added_at ? new Date(p.added_at).toLocaleString() : ''}</span>
                    </div>
                    {p.source_url && (
                      <a
                        href={p.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block mt-0.5 text-xs text-cyan-400 hover:text-cyan-300 truncate max-w-full"
                        title={p.source_url}
                      >
                        {p.source_url}
                      </a>
                    )}
                    <pre className="mt-1 text-xs text-slate-400 truncate max-w-full overflow-hidden" title={p.payload_preview}>
                      {typeof p.payload_preview === 'string' ? p.payload_preview.slice(0, 120) + (p.payload_preview.length > 120 ? '…' : '') : ''}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>

          <div>
            <label className="block text-sm text-slate-300 mb-2">Safe Gadget Chains (JSON) — framework ID → benign payload only</label>
            <p className="text-xs text-slate-500 mb-2">e.g. {`{"CommonsCollections4":"<safe OOB DNS payload>","Jackson":"<safe echo payload>"}`}. No weaponized RCE.</p>
            <textarea
              value={poeGadgetChains}
              onChange={(e) => setPoeGadgetChains(e.target.value)}
              onBlur={() => {
                try {
                  const parsed = JSON.parse(poeGadgetChains)
                  if (typeof parsed === 'object' && parsed !== null) saveConfig('poe_gadget_chains', JSON.stringify(parsed))
                } catch (_) {}
              }}
              className="w-full min-h-[120px] rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-2 text-slate-200 font-mono text-sm"
              placeholder='{"CommonsCollections4":"","Jackson":""}'
            />
          </div>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Used by Exploit Synthesis &amp; Memory Lab. Verified Exploitability Matrix appears in PDF report with cryptographic timestamp.
        </p>
      </section>
    </div>
  )
}
