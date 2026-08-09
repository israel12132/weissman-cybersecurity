import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  CreditCard,
  RefreshCw,
  Building2,
  Radar,
  AlertTriangle,
  ArrowUpRight,
  Shield,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import StatCard from '../components/ui/StatCard'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import Button from '../components/ui/Button'

const PLAN_TIERS = ['starter', 'professional', 'enterprise']

function nextPlanSlug(current) {
  const idx = PLAN_TIERS.indexOf((current || '').toLowerCase())
  if (idx < 0 || idx >= PLAN_TIERS.length - 1) return null
  return PLAN_TIERS[idx + 1]
}

function usagePct(used, max) {
  if (!max || max <= 0) return 0
  return Math.min(100, (used / max) * 100)
}

function usageTone(pct) {
  if (pct >= 90) return 'text-rose-400'
  if (pct >= 70) return 'text-amber-400'
  return 'text-emerald-400'
}

function statusBadgeClass(status) {
  const s = (status || '').toLowerCase()
  if (s === 'active' || s === 'trialing') {
    return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
  }
  if (s === 'past_due' || s === 'paused') {
    return 'bg-amber-500/15 text-amber-300 border-amber-500/30'
  }
  return 'bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border-[var(--border-strong)]'
}

function localeTag(language) {
  return language === 'he' ? 'he-IL' : 'en-US'
}

function formatPeriodEnd(iso, language) {
  if (!iso) return null
  try {
    return new Date(iso).toLocaleDateString(localeTag(language), {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return iso
  }
}

function formatPeriodYm(ym, language) {
  if (!ym || typeof ym !== 'string') return ym
  const [y, m] = ym.split('-')
  if (!y || !m) return ym
  const d = new Date(Number(y), Number(m) - 1, 1)
  if (Number.isNaN(d.getTime())) return ym
  return d.toLocaleDateString(localeTag(language), { year: 'numeric', month: 'long' })
}

function subscriptionStatusLabel(status, t) {
  const slug = (status || 'unknown').toLowerCase().replace(/[^a-z0-9_]/g, '_')
  return t(`pages.billing.status_${slug}`, { defaultValue: status || t('pages.billing.status_unknown') })
}

export default function Billing() {
  const { t, i18n } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [checkoutLoading, setCheckoutLoading] = useState(false)
  const [checkoutError, setCheckoutError] = useState(null)

  const loadUsage = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const body = await apiFetch('/api/billing/usage')
      if (body.ok === false) {
        throw new Error(body.detail || t('pages.billing.load_failed'))
      }
      setData(body)
    } catch (err) {
      setData(null)
      setError(err.message || t('pages.billing.load_failed'))
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    loadUsage()
  }, [loadUsage])

  const subscription = data?.subscription ?? null
  const limits = data?.limits ?? null
  const usage = data?.usage ?? null
  const billingStrict = data?.billing_strict === true

  const upgradeSlug = useMemo(() => {
    const next = nextPlanSlug(subscription?.plan_slug)
    if (next) return next
    if (!subscription?.plan_slug) return 'starter'
    return null
  }, [subscription?.plan_slug])

  const handleUpgrade = async () => {
    if (!upgradeSlug) return
    setCheckoutLoading(true)
    setCheckoutError(null)
    try {
      const body = await apiFetch('/api/billing/checkout-session', {
        method: 'POST',
        body: { plan_slug: upgradeSlug },
      })
      if (!body.checkout_url) {
        throw new Error(t('pages.billing.checkout_url_missing'))
      }
      window.location.assign(body.checkout_url)
    } catch (err) {
      // Preserve the server's actionable `hint` when present (utils error.message
      // only carries detail/message/error, not hint).
      let msg = err.message
      if (err.response) {
        const b = await err.response.json().catch(() => ({}))
        msg = b.detail || b.hint || msg
      }
      setCheckoutError(msg || t('pages.billing.checkout_failed'))
    } finally {
      setCheckoutLoading(false)
    }
  }

  const clientsUsed = usage?.clients ?? 0
  const scansUsed = usage?.scans_this_month ?? 0
  const maxClients = limits?.max_clients ?? 0
  const maxScans = limits?.max_scans_per_month ?? 0
  const clientsPct = usagePct(clientsUsed, maxClients)
  const scansPct = usagePct(scansUsed, maxScans)

  const listFindings = useMemo(() => {
    if (!data) return []
    const rows = []
    if (subscription) {
      rows.push({
        severity: subscription.status === 'active' ? 'info' : 'medium',
        title: subscription.plan_slug || 'subscription',
        type: 'billing',
        description: subscriptionStatusLabel(subscription.status, t),
        resource: formatPeriodEnd(subscription.current_period_end, i18n.language) || '',
      })
    }
    if (usage) {
      rows.push({
        severity: clientsPct >= 90 ? 'critical' : clientsPct >= 70 ? 'high' : 'info',
        title: t('pages.billing.clients_label'),
        type: 'usage',
        description: `${clientsUsed} / ${maxClients}`,
      })
      rows.push({
        severity: scansPct >= 90 ? 'critical' : scansPct >= 70 ? 'high' : 'info',
        title: t('pages.billing.scans_label'),
        type: 'usage',
        description: `${scansUsed} / ${maxScans}`,
      })
    }
    return rows
  }, [data, subscription, usage, clientsUsed, maxClients, scansUsed, maxScans, clientsPct, scansPct, t, i18n.language])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-billing',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource || ''}`,
  })

  const headerActions = (
    <ShellScanActions
      onRefresh={loadUsage}
      onExport={exportCsv}
      refreshLoading={loading}
      exportDisabled={!filteredFindings.length}
    />
  )

  return (
    <PageShell
      title={t('pages.billing.title')}
      subtitle={t('pages.billing.subtitle')}
      icon={<CreditCard className="w-5 h-5 text-cyan-400" strokeWidth={1.75} />}
      badge={billingStrict ? t('pages.billing.badge_enforced') : t('pages.billing.badge_relaxed')}
      badgeColor={billingStrict ? '#fbbf24' : '#22d3ee'}
      actions={headerActions}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t('pages.billing.evidence_notice')}</EvidenceNotice>

        {loading && !data && (
          <SkeletonWidgetGrid count={3} className="lg:grid-cols-3" />
        )}

        {error && !loading && (
          <div
            role="alert"
            className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 flex items-start gap-3"
          >
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="text-sm font-mono text-rose-200">{error}</p>
              <Button variant="unstyled"
                type="button"
                onClick={loadUsage}
                className="mt-2 text-[11px] font-mono uppercase tracking-widest text-rose-300/80 hover:text-rose-200"
              >
                {t('common.retry')}
              </Button>
            </div>
          </div>
        )}

        {!loading && !error && data && !subscription && (
          <EmptyState
            icon={<CreditCard className="w-6 h-6 text-cyan-400" strokeWidth={1.75} />}
            title={t('pages.billing.no_subscription_title')}
            body={t('pages.billing.no_subscription_body')}
            cta={
              upgradeSlug
                ? {
                    label: t('pages.billing.start_checkout'),
                    onClick: handleUpgrade,
                  }
                : undefined
            }
          />
        )}

        {!error && subscription && (
          <>
            <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-5 sm:p-6">
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                    {t('pages.billing.current_plan')}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-3">
                    <h2 className="text-2xl font-bold text-white tracking-tight">
                      {subscription.plan_name || subscription.plan_slug || '—'}
                    </h2>
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-widest ${statusBadgeClass(subscription.status)}`}
                    >
                      {subscriptionStatusLabel(subscription.status, t)}
                    </span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-[var(--text-muted)]">
                    <span>{t('pages.billing.slug_label', { slug: subscription.plan_slug || '—' })}</span>
                    {subscription.current_period_end && (
                      <span>{t('pages.billing.renews_label', { date: formatPeriodEnd(subscription.current_period_end, i18n.language) })}</span>
                    )}
                    {usage?.period && (
                      <span>{t('pages.billing.usage_period_label', { period: formatPeriodYm(usage.period, i18n.language) })}</span>
                    )}
                  </div>
                </div>

                <div className="flex flex-col items-stretch sm:items-end gap-2 shrink-0">
                  {upgradeSlug ? (
                    <Button variant="unstyled"
                      type="button"
                      onClick={handleUpgrade}
                      disabled={checkoutLoading}
                      className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-sm font-mono text-cyan-100 hover:bg-cyan-500/25 transition-colors disabled:opacity-50"
                    >
                      {checkoutLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          {t('pages.billing.opening_checkout')}
                        </>
                      ) : (
                        <>
                          {t('pages.billing.upgrade_to', { plan: upgradeSlug })}
                          <ArrowUpRight className="w-4 h-4" />
                        </>
                      )}
                    </Button>
                  ) : (
                    <div className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[11px] font-mono text-[var(--text-tertiary)]">
                      <Shield className="w-3.5 h-3.5" />
                      {t('pages.billing.highest_tier')}
                    </div>
                  )}
                  {billingStrict && (
                    <p className="text-[10px] font-mono text-amber-300/70 text-right max-w-xs">
                      {t('pages.billing.enforcement_notice')}
                    </p>
                  )}
                </div>
              </div>

              {checkoutError && (
                <div
                  role="alert"
                  className="mt-4 rounded-lg border border-rose-500/25 bg-rose-500/10 px-3 py-2 text-[12px] font-mono text-rose-200"
                >
                  {checkoutError}
                </div>
              )}
            </section>

            {usage && limits && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <StatCard
                    label={t('pages.billing.clients_label')}
                    value={clientsUsed}
                    hint={maxClients > 0 ? t('pages.billing.clients_max_hint', { max: maxClients }) : t('pages.billing.clients_no_limit')}
                    footer={
                      maxClients > 0 ? (
                        <span className={usageTone(clientsPct)}>
                          {t('pages.billing.clients_capacity', { pct: clientsPct.toFixed(1) })}
                        </span>
                      ) : null
                    }
                  />
                  <StatCard
                    label={t('pages.billing.scans_label')}
                    value={scansUsed}
                    hint={maxScans > 0 ? t('pages.billing.scans_max_hint', { max: maxScans }) : t('pages.billing.scans_no_limit')}
                    footer={
                      maxScans > 0 ? (
                        <span className={usageTone(scansPct)}>
                          {t('pages.billing.scans_quota', { pct: scansPct.toFixed(1) })}
                        </span>
                      ) : null
                    }
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <UsageMeter
                    icon={Building2}
                    label={t('pages.billing.client_roster')}
                    used={clientsUsed}
                    max={maxClients}
                  />
                  <UsageMeter
                    icon={Radar}
                    label={t('pages.billing.monthly_scans')}
                    used={scansUsed}
                    max={maxScans}
                  />
                </div>
              </>
            )}

            {subscription && !usage && (
              <EmptyState
                compact
                icon="alert"
                title={t('pages.billing.usage_unavailable_title')}
                body={t('pages.billing.usage_unavailable_body')}
                cta={{ label: t('common.refresh'), onClick: loadUsage }}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}

function UsageMeter({ icon: Icon, label, used, max }) {
  const pct = usagePct(used, max)
  const tone = usageTone(pct)

  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--card-bg)]/60 backdrop-blur-md p-5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="w-4 h-4 text-cyan-400/80 shrink-0" strokeWidth={1.75} />
          <span className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-tertiary)] truncate">
            {label}
          </span>
        </div>
        <span className={`text-sm font-mono tabular-nums ${tone}`}>
          {used}
          <span className="text-[var(--text-muted)]"> / {max > 0 ? max : '—'}</span>
        </span>
      </div>
      <div className="h-2 rounded-full bg-[var(--bg-2)] overflow-hidden border border-[var(--border-subtle)]">
        <div
          className={`h-full transition-all duration-500 ${
            pct >= 90 ? 'bg-rose-500' : pct >= 70 ? 'bg-amber-400' : 'bg-cyan-500'
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
