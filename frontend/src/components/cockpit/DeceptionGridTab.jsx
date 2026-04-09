/**
 * CNAPP Layer 4: Deception Grid — honeytokens, active cloud injection map, CRITICAL on trigger.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { ShieldAlert, Plus, MapPin, AlertTriangle, Key, Cloud, Loader2 } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const ASSET_TYPES = [
  { value: 'api_key', label: 'API Key' },
  { value: 'aws_key', label: 'AWS Key' },
  { value: 'db_cred', label: 'DB Credential' },
  { value: 'shadow_endpoint', label: 'Shadow Endpoint' },
]

function parseAssetIds(raw) {
  return raw
    .split(/[,\s]+/)
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n > 0)
}

export default function DeceptionGridTab() {
  const { selectedClientId } = useClient()
  const { lastTelemetry } = useWarRoom?.() || {}
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [deploying, setDeploying] = useState(false)
  const [typesToGenerate, setTypesToGenerate] = useState(['api_key', 'aws_key', 'db_cred'])
  const [deployForm, setDeployForm] = useState({
    asset_ids: '',
    s3_bucket: '',
    s3_object_key: '',
    s3_region: '',
    ssm_parameter_path: '',
  })
  const [deployMsg, setDeployMsg] = useState(null)

  const fetchAssets = useCallback(async () => {
    if (!selectedClientId) {
      setAssets([])
      return
    }
    setLoading(true)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/deception`)
      if (r.ok) {
        const d = await r.json()
        const list = Array.isArray(d) ? d : (d.assets ?? [])
        setAssets(list)
      }
    } catch (_) {
      setAssets([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  useEffect(() => {
    fetchAssets()
  }, [fetchAssets])

  useEffect(() => {
    const t =
      lastTelemetry?.event === 'deception_triggered' &&
      String(lastTelemetry?.client_id ?? '') === String(selectedClientId ?? '')
    if (t) fetchAssets()
  }, [lastTelemetry, selectedClientId, fetchAssets])

  const generate = async () => {
    if (!selectedClientId) return
    setGenerating(true)
    try {
      await apiFetch(`/api/clients/${selectedClientId}/deception/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ types: typesToGenerate, tech_hint: 'generic' }),
      })
      await fetchAssets()
    } catch (_) {}
    setGenerating(false)
  }

  const deployCloud = async () => {
    if (!selectedClientId) return
    const ids = parseAssetIds(deployForm.asset_ids)
    if (ids.length === 0) {
      setDeployMsg({ ok: false, text: 'Enter one or more asset IDs (comma-separated).' })
      return
    }
    setDeploying(true)
    setDeployMsg(null)
    try {
      const body = {
        asset_ids: ids,
        s3_bucket: deployForm.s3_bucket.trim() || undefined,
        s3_object_key: deployForm.s3_object_key.trim() || undefined,
        s3_region: deployForm.s3_region.trim() || undefined,
        ssm_parameter_path: deployForm.ssm_parameter_path.trim() || undefined,
      }
      const r = await apiFetch(`/api/clients/${selectedClientId}/deception/deploy-cloud`, {
        method: 'POST',
        headers: destructiveHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok && d.ok) {
        setDeployMsg({
          ok: true,
          text: `Deployed ${d.deployed ?? 0}. ${(d.errors || []).length ? d.errors.join('; ') : ''}`,
        })
      } else {
        setDeployMsg({ ok: false, text: d.detail || JSON.stringify(d) || r.statusText })
      }
      await fetchAssets()
    } catch (e) {
      setDeployMsg({ ok: false, text: String(e) })
    }
    setDeploying(false)
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        Select a client to manage deception assets.
      </div>
    )
  }

  const triggered = assets.filter(a => a.status === 'triggered')
  const injected = assets.filter(a => a.cloud_injection_uri)

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-5 h-5 text-amber-400" />
        <h2 className="text-lg font-semibold text-white">Deception Grid</h2>
      </div>

      {triggered.length > 0 && (
        <div className="rounded-xl border border-red-500/50 bg-red-500/10 px-4 py-3 flex items-center gap-2 text-red-400">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span className="font-medium">{triggered.length} honeytoken(s) triggered — CRITICAL. Attacker fingerprint logged.</span>
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-3">Active cloud injection (STS assume-role)</h3>
        <p className="text-[11px] text-white/50 mb-3">
          Configure the client&apos;s cross-account role (Phase 3). For <code className="text-[#22d3ee]">aws_key</code> set S3 bucket + object key;
          for <code className="text-[#22d3ee]">db_cred</code> / <code className="text-[#22d3ee]">api_key</code> set SSM parameter path. Forward CloudTrail /
          GuardDuty JSON to <code className="text-[#22d3ee]">POST /api/deception/aws-events</code> with header{' '}
          <code className="text-[#22d3ee]">X-Weissman-Signature: sha256=…</code> (HMAC-SHA256 body, secret{' '}
          <code className="text-[#22d3ee]">WEISSMAN_DECEPTION_WEBHOOK_SECRET</code>).
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input
            type="text"
            placeholder="Asset IDs (e.g. 12, 14)"
            value={deployForm.asset_ids}
            onChange={e => setDeployForm(f => ({ ...f, asset_ids: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm md:col-span-2"
          />
          <input
            type="text"
            placeholder="S3 bucket"
            value={deployForm.s3_bucket}
            onChange={e => setDeployForm(f => ({ ...f, s3_bucket: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="S3 object key"
            value={deployForm.s3_object_key}
            onChange={e => setDeployForm(f => ({ ...f, s3_object_key: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="S3 region (optional)"
            value={deployForm.s3_region}
            onChange={e => setDeployForm(f => ({ ...f, s3_region: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="SSM parameter path (e.g. /weissman/honey/db)"
            value={deployForm.ssm_parameter_path}
            onChange={e => setDeployForm(f => ({ ...f, ssm_parameter_path: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
        </div>
        <button
          type="button"
          onClick={deployCloud}
          disabled={deploying}
          className="mt-3 flex items-center gap-2 px-4 py-2 rounded-xl border border-sky-500/50 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20 disabled:opacity-50"
        >
          {deploying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Cloud className="w-4 h-4" />}
          {deploying ? 'Injecting…' : 'Deploy to tenant AWS'}
        </button>
        {deployMsg && (
          <p className={`mt-2 text-xs ${deployMsg.ok ? 'text-[#10b981]' : 'text-red-400'}`}>{deployMsg.text}</p>
        )}
      </div>

      {injected.length > 0 && (
        <div className="rounded-2xl border border-sky-500/20 bg-sky-500/5 p-4">
          <h4 className="text-xs font-medium text-sky-300 mb-2 flex items-center gap-2">
            <MapPin className="w-4 h-4" /> Cloud injection map
          </h4>
          <ul className="space-y-1 text-[11px] font-mono text-white/70">
            {injected.map(a => (
              <li key={a.id} className="truncate" title={a.cloud_injection_uri}>
                #{a.id} {a.asset_type}: {a.cloud_injection_uri}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-3">Generate honeytokens</h3>
        <div className="flex flex-wrap gap-2 mb-3">
          {ASSET_TYPES.map(({ value, label }) => (
            <label key={value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={typesToGenerate.includes(value)}
                onChange={e => {
                  if (e.target.checked) setTypesToGenerate(t => [...t, value])
                  else setTypesToGenerate(t => t.filter(x => x !== value))
                }}
                className="rounded border-white/20"
              />
              <span className="text-sm text-white/80">{label}</span>
            </label>
          ))}
        </div>
        <button
          type="button"
          onClick={generate}
          disabled={generating}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 disabled:opacity-50"
        >
          <Plus className="w-4 h-4" />
          {generating ? 'Generating…' : 'Generate tokens'}
        </button>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <span className="text-sm font-medium text-white/90">Honeytoken inventory</span>
          <button type="button" onClick={fetchAssets} className="text-xs text-[#22d3ee] hover:underline">
            Refresh
          </button>
        </div>
        {loading ? (
          <div className="p-6 text-center text-white/50 text-sm">Loading…</div>
        ) : assets.length === 0 ? (
          <div className="p-6 text-center text-white/50 text-sm">No deception assets. Generate tokens, then deploy to AWS above.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
            {assets.map(a => (
              <div
                key={a.id}
                className={`rounded-xl border p-3 ${
                  a.status === 'triggered' ? 'border-red-500/50 bg-red-500/10' : 'border-white/10 bg-black/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-amber-400" />
                  <span className="text-xs font-medium text-white/90">
                    #{a.id} {a.asset_type}
                  </span>
                  {a.status === 'triggered' && <AlertTriangle className="w-4 h-4 text-red-400 ml-auto" />}
                </div>
                <div className="mt-1 font-mono text-[10px] text-white/60 truncate" title={a.token_value_masked}>
                  {a.token_value_masked || '••••'}
                </div>
                {a.canary_access_key_id ? (
                  <div className="mt-1 text-[9px] text-amber-200/80 font-mono truncate" title={a.canary_access_key_id}>
                    canary AKIA: {a.canary_access_key_id}
                  </div>
                ) : null}
                {a.deployment_location && (
                  <div className="mt-1 flex items-center gap-1 text-[10px] text-white/50">
                    <MapPin className="w-3 h-3 shrink-0" />
                    <span className="truncate">{a.deployment_location}</span>
                  </div>
                )}
                {a.cloud_injection_uri && (
                  <div className="mt-1 flex items-start gap-1 text-[10px] text-sky-300/90">
                    <Cloud className="w-3 h-3 shrink-0 mt-0.5" />
                    <span className="break-all">{a.cloud_injection_uri}</span>
                  </div>
                )}
                <div className="mt-1 text-[10px]">
                  <span className={a.status === 'triggered' ? 'text-red-400' : 'text-[#10b981]'}>{a.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
