import React, { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ChevronDown } from 'lucide-react'
import { getCommandCenterRoute } from '../../lib/engineParamDefs.js'

const CREDENTIAL_PATTERN = /aws_|gcp_|azure_|github|token|password|oauth|secret|pem|ssh|oast|llm_|auth_header|cookies|external_id|bearer|api_key/i
const ADVANCED_PATTERN = /timeout|concurrency|max_|threshold|decay|planner|halflife|expansion|corroboration|belief|fusion|variants|rotation|pool/i

function groupParams(schema) {
  const credentials = []
  const advanced = []
  const core = []
  for (const def of schema) {
    const key = def.key || ''
    if (CREDENTIAL_PATTERN.test(key) || def.type === 'password') credentials.push(def)
    else if (ADVANCED_PATTERN.test(key)) advanced.push(def)
    else core.push(def)
  }
  return { core, credentials, advanced }
}

export function EngineParamField({ def, value, onChange, disabled }) {
  const base = 'bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50'
  const label = (
    <label className="block text-[11px] font-mono text-[var(--text-tertiary)] uppercase tracking-wider mb-1">
      {def.label}
      {def.type === 'password' && (
        <span className="ml-1 text-amber-400/80 normal-case tracking-normal" title="Stored securely; masked values are not overwritten">
          🔒
        </span>
      )}
    </label>
  )
  if (def.type === 'select') {
    return (
      <div>
        {label}
        <select value={value} onChange={(e) => onChange(def.key, e.target.value)} disabled={disabled} className={`${base} w-full`}>
          {(def.options || []).map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      </div>
    )
  }
  if (def.type === 'textarea') {
    return (
      <div>
        {label}
        <textarea value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} rows={3} className={`${base} w-full resize-y`} />
      </div>
    )
  }
  if (def.type === 'password') {
    return (
      <div>
        {label}
        <input type="password" autoComplete="off" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} className={`${base} w-full`} />
      </div>
    )
  }
  if (def.type === 'number') {
    return (
      <div>
        {label}
        <input type="number" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} min={def.min} max={def.max} disabled={disabled} className={`${base} w-full`} />
      </div>
    )
  }
  return (
    <div>
      {label}
      <input type="text" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} className={`${base} w-full`} />
    </div>
  )
}

function ParamSection({ title, defs, values, onChange, disabled, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  if (!defs.length) return null
  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((s) => !s)}
        className="w-full flex items-center justify-between px-3 py-2 text-left text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] hover:bg-[var(--row-hover-bg)]"
      >
        <span>{title}</span>
        <span className="text-[var(--text-disabled)]">{open ? '−' : '+'}</span>
      </button>
      {open && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 px-3 pb-3 border-t border-[var(--border-subtle)] pt-3">
          {defs.map((def) => (
            <EngineParamField
              key={def.key}
              def={def}
              value={values[def.key] ?? def.defaultVal ?? ''}
              onChange={onChange}
              disabled={disabled}
            />
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * Professional scan-parameter panel: grouped fields, integrations link, command-center hub.
 */
export default function EngineScanParamsPanel({
  engineId,
  schema,
  values,
  onChange,
  clientId,
  disabled = false,
  compact = false,
  maxVisible = 0,
  collapsible = false,
  defaultCollapsed = false,
  className = '',
}) {
  const { t } = useTranslation()
  const [collapsed, setCollapsed] = useState(defaultCollapsed)
  const hubRoute = engineId ? getCommandCenterRoute(engineId) : null
  const groups = useMemo(() => groupParams(schema || []), [schema])

  if (!schema?.length) return null

  const flat = [...groups.core, ...groups.credentials, ...groups.advanced]
  const visible = compact && maxVisible > 0 ? flat.slice(0, maxVisible) : null
  const filledCount = flat.filter((d) => {
    const v = values[d.key] ?? d.defaultVal ?? ''
    return v !== '' && v != null
  }).length

  const header = (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest flex items-center gap-2">
        {collapsible && (
          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            className="p-0.5 rounded hover:bg-[var(--row-hover-bg)] text-[var(--text-tertiary)]"
            aria-expanded={!collapsed}
          >
            <ChevronDown className={`w-3.5 h-3.5 transition-transform ${collapsed ? '' : 'rotate-180'}`} />
          </button>
        )}
        {t('components.engineScanParams.title')}
        {' · '}
        <span className="text-cyan-400/80">{schema.length}</span>
        {filledCount > 0 && (
          <span className="text-emerald-400/70 normal-case tracking-normal">
            ({filledCount} {t('components.engineScanParams.filled')})
          </span>
        )}
      </span>
      <div className="flex flex-wrap gap-2 text-[10px] font-mono">
        {clientId && (
          <Link
            to={`/clients/${clientId}/integrations`}
            className="text-amber-300/90 hover:text-amber-200 border border-amber-500/30 rounded px-2 py-0.5"
          >
            {t('components.engineScanParams.integrations')}
          </Link>
        )}
        {hubRoute && (
          <Link to={hubRoute} className="text-violet-300/90 hover:text-violet-200 border border-violet-500/30 rounded px-2 py-0.5">
            {t('components.engineScanParams.command_center')}
          </Link>
        )}
      </div>
    </div>
  )

  return (
    <div className={`space-y-3 rounded-xl border border-[var(--border-default)] bg-[var(--bg-1)] px-4 py-3 ${className}`}>
      {header}
      {(!collapsible || !collapsed) && (
        <>
      {visible ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {visible.map((def) => (
            <EngineParamField
              key={def.key}
              def={def}
              value={values[def.key] ?? def.defaultVal ?? ''}
              onChange={onChange}
              disabled={disabled}
            />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          <ParamSection
            title={t('components.engineScanParams.section_core')}
            defs={groups.core}
            values={values}
            onChange={onChange}
            disabled={disabled}
            defaultOpen
          />
          <ParamSection
            title={t('components.engineScanParams.section_credentials')}
            defs={groups.credentials}
            values={values}
            onChange={onChange}
            disabled={disabled}
            defaultOpen={groups.credentials.length <= 6}
          />
          <ParamSection
            title={t('components.engineScanParams.section_advanced')}
            defs={groups.advanced}
            values={values}
            onChange={onChange}
            disabled={disabled}
            defaultOpen={false}
          />
        </div>
      )}

      {clientId && groups.credentials.length > 0 && (
        <p className="text-[10px] text-[var(--text-muted)] font-mono leading-relaxed">
          {t('components.engineScanParams.secrets_hint')}
        </p>
      )}
        </>
      )}
    </div>
  )
}
