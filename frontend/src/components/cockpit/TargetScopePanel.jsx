import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../utils/apiFetch'
import { confirmDialog } from '../../utils/confirmDialog'
import Button from '../ui/Button'

const NS = 'components.cockpitWidgets.targetScopePanel'

function parseJsonArray(val) {
  if (val == null) return []
  if (Array.isArray(val)) return val.map(String)
  if (typeof val !== 'string') return []
  try {
    const arr = JSON.parse(val)
    return Array.isArray(arr) ? arr.map(String) : []
  } catch (_) {
    return []
  }
}

function CopyableTag({ value }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }, [value])
  return (
    <span
      role="button"
      tabIndex={0}
      onClick={copy}
      onKeyDown={(e) => e.key === 'Enter' && copy()}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-0)]/40 text-[var(--text-secondary)] font-mono text-xs cursor-pointer hover:border-[#22d3ee]/50 hover:text-[#22d3ee] transition-all"
    >
      <span className="truncate max-w-[140px]">{value}</span>
      <span className="text-[10px] shrink-0">{copied ? t(`${NS}.copied`) : t(`${NS}.copy`)}</span>
    </span>
  )
}

export default function TargetScopePanel({ ceoIntegrated = false }) {
  const { t } = useTranslation()
  const { selectedClient, selectedClientId, clientConfig, patchConfig, configLoading } = useClient()
  const [zeroDayFindings, setZeroDayFindings] = useState([])
  const [loading, setLoading] = useState(false)

  const domains = parseJsonArray(selectedClient?.domains)
  const ipRanges = parseJsonArray(selectedClient?.ip_ranges)
  const techStack = parseJsonArray(selectedClient?.tech_stack)

  useEffect(() => {
    if (!selectedClientId) {
      setZeroDayFindings([])
      return
    }
    setLoading(true)
    apiFetch(`/api/clients/${selectedClientId}/findings`)
      .then((d) => {
        const list = Array.isArray(d.findings) ? d.findings : []
        setZeroDayFindings(list.filter((f) => (f.source || '').toLowerCase().includes('zero_day') || (f.source || '').toLowerCase().includes('zero-day')))
      })
      .catch(() => setZeroDayFindings([]))
      .finally(() => setLoading(false))
  }, [selectedClientId])

  if (!selectedClientId || !selectedClient) {
    if (ceoIntegrated) {
      return null
    }
    return (
      <aside className="hidden lg:flex w-full lg:w-72 lg:max-w-[18rem] shrink-0 border-t lg:border-t-0 lg:border-l border-[var(--border-default)] bg-[var(--bg-0)]/40 backdrop-blur-md flex-col items-center justify-center p-6 text-[var(--text-tertiary)]">
        <p className="text-sm">{t(`${NS}.selectClient`)}</p>
      </aside>
    )
  }

  return (
    <aside className="w-full max-w-full lg:w-72 lg:max-w-[18rem] shrink-0 border-t lg:border-t-0 lg:border-l border-[var(--border-default)] bg-[var(--bg-0)]/40 backdrop-blur-md overflow-y-auto overflow-x-hidden flex flex-col max-h-[min(36vh,280px)] lg:max-h-none lg:h-full">
      <div className="p-4 border-b border-[var(--border-default)]">
        <h2 className="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)] font-medium">{t(`${NS}.title`)}</h2>
        <p className="text-sm font-medium text-[var(--text-primary)] mt-1 truncate">{selectedClient.name}</p>
      </div>

      <div className="p-4 space-y-4">
        <section className="rounded-xl border border-amber-500/25 bg-amber-950/20 p-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-[10px] uppercase tracking-widest text-amber-200/80 font-medium">{t(`${NS}.otTitle`)}</h3>
              <p className="text-[10px] text-[var(--text-tertiary)] mt-1 leading-snug">
                {t(`${NS}.otDescription`)}
              </p>
            </div>
            <Button variant="unstyled"
              type="button"
              disabled={configLoading}
              role="switch"
              aria-checked={!!clientConfig.industrial_ot_enabled}
              onClick={async () => {
                const next = !clientConfig.industrial_ot_enabled
                if (next) {
                  const ok = await confirmDialog({
                    title: t(`${NS}.otTitle`),
                    message: t(`${NS}.otEnableConfirm`),
                    confirmLabel: t(`${NS}.otEnableAction`),
                    variant: 'warning',
                  })
                  if (!ok) return
                }
                patchConfig(selectedClientId, { industrial_ot_enabled: next })
              }}
              className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${clientConfig.industrial_ot_enabled ? 'bg-amber-500/80' : 'bg-[var(--border-strong)]'} ${configLoading ? 'opacity-50' : ''}`}
            >
              <span
                className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-[var(--text-primary)] shadow transition-transform ${clientConfig.industrial_ot_enabled ? 'translate-x-5' : ''}`}
              />
            </Button>
          </div>
        </section>

        <section>
          <h3 className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)] font-medium mb-2">{t(`${NS}.domainsIps`)}</h3>
          <div className="flex flex-wrap gap-2">
            {domains.length === 0 && ipRanges.length === 0 ? (
              <span className="text-xs text-[var(--text-muted)]">{t(`${NS}.noneConfigured`)}</span>
            ) : (
              <>
                {domains.map((d) => (
                  <CopyableTag key={d} value={d} />
                ))}
                {ipRanges.map((ip) => (
                  <CopyableTag key={ip} value={ip} />
                ))}
              </>
            )}
          </div>
        </section>

        <section>
          <h3 className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)] font-medium mb-2">{t(`${NS}.techStack`)}</h3>
          <div className="flex flex-wrap gap-2">
            {techStack.length === 0 ? (
              <span className="text-xs text-[var(--text-muted)]">{t(`${NS}.techStackEmpty`)}</span>
            ) : (
              techStack.map((tech) => (
                <span
                  key={tech}
                  className="px-2 py-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-0)]/40 text-[var(--text-secondary)] font-mono text-xs"
                >
                  {tech}
                </span>
              ))
            )}
          </div>
        </section>

        <section>
          <h3 className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)] font-medium mb-2">{t(`${NS}.zeroDayTitle`)}</h3>
          {loading ? (
            <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.loading`)}</p>
          ) : zeroDayFindings.length === 0 ? (
            <p className="text-xs text-[#4ade80]/90">{t(`${NS}.noZeroDay`)}</p>
          ) : (
            <ul className="space-y-2">
              {zeroDayFindings.slice(0, 10).map((f) => (
                <li
                  key={f.id}
                  className="text-xs border-l-2 border-[#ef4444] pl-2 py-1 bg-red-500/10 text-red-300/90 rounded-r-lg"
                >
                  <span className="font-medium">{f.title || t(`${NS}.findingFallback`)}</span>
                  {f.severity && (
                    <span className="ml-1 text-[10px] text-[var(--text-tertiary)]">({f.severity})</span>
                  )}
                </li>
              ))}
              {zeroDayFindings.length > 10 && (
                <li className="text-[10px] text-[var(--text-muted)]">{t(`${NS}.moreCount`, { count: zeroDayFindings.length - 10 })}</li>
              )}
            </ul>
          )}
        </section>
      </div>
    </aside>
  )
}
