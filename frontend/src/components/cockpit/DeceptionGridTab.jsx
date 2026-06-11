/**
 * CNAPP Layer 4: Deception Grid — honeytokens, active cloud injection map, CRITICAL on trigger.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { ShieldAlert, Plus, MapPin, AlertTriangle, Key, Cloud, Loader2 } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const NS = 'components.cockpitTabs.deceptionGrid'

const ASSET_TYPE_VALUES = ['api_key', 'aws_key', 'db_cred', 'shadow_endpoint']

function parseAssetIds(raw) {
  return raw
    .split(/[,\s]+/)
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n > 0)
}

export default function DeceptionGridTab() {
  const { t } = useTranslation()
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

  const assetTypes = useMemo(
    () => ASSET_TYPE_VALUES.map(value => ({ value, label: t(`${NS}.assetTypes.${value}`) })),
    [t],
  )

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
    const triggered =
      lastTelemetry?.event === 'deception_triggered' &&
      String(lastTelemetry?.client_id ?? '') === String(selectedClientId ?? '')
    if (triggered) fetchAssets()
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
      setDeployMsg({ ok: false, text: t(`${NS}.enterAssetIds`) })
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
          text: t(`${NS}.deployed`, {
            count: d.deployed ?? 0,
            errors: (d.errors || []).length ? d.errors.join('; ') : '',
          }),
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
        {t(`${NS}.selectClient`)}
      </div>
    )
  }

  const triggered = assets.filter(a => a.status === 'triggered')
  const injected = assets.filter(a => a.cloud_injection_uri)

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-5 h-5 text-amber-400" />
        <h2 className="text-lg font-semibold text-white">{t(`${NS}.title`)}</h2>
      </div>

      {triggered.length > 0 && (
        <div className="rounded-xl border border-red-500/50 bg-red-500/10 px-4 py-3 flex items-center gap-2 text-red-400">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span className="font-medium">{t(`${NS}.triggeredAlert`, { count: triggered.length })}</span>
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-3">{t(`${NS}.cloudInjectionTitle`)}</h3>
        <p className="text-[11px] text-white/50 mb-3">
          {t(`${NS}.cloudInjectionHintBeforeAwsKey`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintAwsKey`)}</code>
          {t(`${NS}.cloudInjectionHintMiddle`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintDbCred`)}</code>
          {t(`${NS}.cloudInjectionHintAnd`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintApiKey`)}</code>
          {t(`${NS}.cloudInjectionHintAfterTypes`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintEndpoint`)}</code>
          {t(`${NS}.cloudInjectionHintWithHeader`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintSignature`)}</code>
          {t(`${NS}.cloudInjectionHintHmac`)}
          <code className="text-[#22d3ee]">{t(`${NS}.cloudInjectionHintSecret`)}</code>
          {t(`${NS}.cloudInjectionHintEnd`)}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input
            type="text"
            placeholder={t(`${NS}.assetIds`)}
            value={deployForm.asset_ids}
            onChange={e => setDeployForm(f => ({ ...f, asset_ids: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm md:col-span-2"
          />
          <input
            type="text"
            placeholder={t(`${NS}.s3Bucket`)}
            value={deployForm.s3_bucket}
            onChange={e => setDeployForm(f => ({ ...f, s3_bucket: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.s3ObjectKey`)}
            value={deployForm.s3_object_key}
            onChange={e => setDeployForm(f => ({ ...f, s3_object_key: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.s3Region`)}
            value={deployForm.s3_region}
            onChange={e => setDeployForm(f => ({ ...f, s3_region: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.ssmParameterPath`)}
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
          {deploying ? t(`${NS}.injecting`) : t(`${NS}.deployButton`)}
        </button>
        {deployMsg && (
          <p className={`mt-2 text-xs ${deployMsg.ok ? 'text-[#10b981]' : 'text-red-400'}`}>{deployMsg.text}</p>
        )}
      </div>

      {injected.length > 0 && (
        <div className="rounded-2xl border border-sky-500/20 bg-sky-500/5 p-4">
          <h4 className="text-xs font-medium text-sky-300 mb-2 flex items-center gap-2">
            <MapPin className="w-4 h-4" /> {t(`${NS}.cloudInjectionMap`)}
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
        <h3 className="text-sm font-medium text-white/90 mb-3">{t(`${NS}.generateHoneytokens`)}</h3>
        <div className="flex flex-wrap gap-2 mb-3">
          {assetTypes.map(({ value, label }) => (
            <label key={value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={typesToGenerate.includes(value)}
                onChange={e => {
                  if (e.target.checked) setTypesToGenerate(prev => [...prev, value])
                  else setTypesToGenerate(prev => prev.filter(x => x !== value))
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
          {generating ? t(`${NS}.generating`) : t(`${NS}.generateTokens`)}
        </button>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <span className="text-sm font-medium text-white/90">{t(`${NS}.honeytokenInventory`)}</span>
          <button type="button" onClick={fetchAssets} className="text-xs text-[#22d3ee] hover:underline">
            {t(`${NS}.refresh`)}
          </button>
        </div>
        {loading ? (
          <div className="p-6 text-center text-white/50 text-sm">{t(`${NS}.loading`)}</div>
        ) : assets.length === 0 ? (
          <div className="p-6 text-center text-white/50 text-sm">{t(`${NS}.noAssets`)}</div>
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
                    {t(`${NS}.canaryAkia`, { id: a.canary_access_key_id })}
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
