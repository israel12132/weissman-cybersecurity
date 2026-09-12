/**
 * SCIM 2.0 tenant provisioning — mint hashed bearers for Okta / Entra / Google.
 * Live GET/POST /api/admin/scim/tokens and GET /api/admin/scim/audit.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyRound, Shield } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import Button from '../components/ui/Button'

const NS = 'pages.scimProvisioning'

export default function ScimProvisioning() {
  const { t } = useTranslation()
  const [tokens, setTokens] = useState([])
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [name, setName] = useState('okta-prod')
  const [minted, setMinted] = useState('')
  const [minting, setMinting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [tok, aud] = await Promise.all([
        api.get('/api/admin/scim/tokens'),
        api.get('/api/admin/scim/audit'),
      ])
      setTokens(Array.isArray(tok?.tokens) ? tok.tokens : [])
      setEvents(Array.isArray(aud?.events) ? aud.events : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setTokens([])
      setEvents([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const listRows = useMemo(
    () =>
      tokens.map((tok) => ({
        id: tok.id,
        severity: tok.revoked_at ? 'low' : 'high',
        title: tok.name,
        type: tok.token_prefix,
        description: tok.last_used_at || tok.created_at || '',
        resource: tok.revoked_at ? 'revoked' : 'active',
      })),
    [tokens],
  )

  const { filteredFindings, searchQuery, setSearchQuery } = useFindingsWorkbench(listRows, {
    csvPrefix: 'weissman-scim-tokens',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleTokens = useMemo(() => {
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return tokens.filter((tok) => ids.has(String(tok.id)))
  }, [tokens, filteredFindings])

  const mint = async () => {
    setMinting(true)
    setError('')
    setMinted('')
    try {
      const res = await api.post('/api/admin/scim/tokens', { name })
      if (res?.ok === false) throw new Error(res.detail || 'mint failed')
      setMinted(res.token || '')
      await load()
    } catch (e) {
      setError(e.message || t(`${NS}.mint_failed`))
    } finally {
      setMinting(false)
    }
  }

  const revoke = async (id) => {
    setError('')
    try {
      await api.delete(`/api/admin/scim/tokens/${encodeURIComponent(id)}`)
      await load()
    } catch (e) {
      setError(e.message || t(`${NS}.revoke_failed`))
    }
  }

  const exportCsv = () => {
    downloadCsv(
      visibleTokens.map((tok) => [
        tok.id,
        tok.name,
        tok.token_prefix,
        tok.last_used_at || '',
        tok.revoked_at || '',
        tok.created_at || '',
      ]),
      ['id', 'name', 'prefix', 'last_used_at', 'revoked_at', 'created_at'],
      'weissman-scim-tokens',
    )
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#a78bfa"
      icon={<KeyRound className="w-5 h-5" />}
      hideEvidence
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!visibleTokens.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-violet-300" aria-hidden />
            {t(`${NS}.mint_heading`)}
          </h2>
          <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.mint_hint`)}</p>
          <div className="flex flex-wrap gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)]"
              aria-label={t(`${NS}.token_name`)}
            />
            <Button
              variant="unstyled"
              type="button"
              data-testid="scim-mint-btn"
              disabled={minting || !name.trim()}
              onClick={mint}
              className="px-3 py-1.5 rounded-lg bg-violet-600 text-white text-xs font-medium hover:bg-violet-500 disabled:opacity-40"
            >
              {t(`${NS}.mint`)}
            </Button>
          </div>
          {minted && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/20 p-3">
              <div className="text-[10px] uppercase tracking-widest text-amber-300 mb-1">
                {t(`${NS}.shown_once`)}
              </div>
              <code className="text-[11px] break-all text-amber-50">{minted}</code>
              <p className="text-[10px] text-[var(--text-muted)] mt-2">{t(`${NS}.base_path`)}</p>
            </div>
          )}
        </div>

        <WeissmanListToolbar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          resultCount={visibleTokens.length}
          totalCount={tokens.length}
        />

        {loading && tokens.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.loading`)}</p>
        ) : visibleTokens.length === 0 ? (
          <EmptyState icon="shield" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
        ) : (
          <ul className="space-y-2">
            {visibleTokens.map((tok) => (
              <li
                key={tok.id}
                className="flex items-center justify-between gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="text-sm text-white truncate">{tok.name}</div>
                  <div className="text-[10px] font-mono text-[var(--text-muted)]">
                    {tok.token_prefix}… · {tok.revoked_at ? t(`${NS}.revoked`) : t(`${NS}.active`)}
                  </div>
                </div>
                {!tok.revoked_at && (
                  <Button
                    variant="unstyled"
                    type="button"
                    data-testid={`scim-revoke-${tok.id}`}
                    onClick={() => revoke(tok.id)}
                    className="px-2 py-1 text-[10px] font-mono rounded border border-rose-500/40 text-rose-200"
                  >
                    {t(`${NS}.revoke`)}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}

        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
            {t(`${NS}.audit_heading`)}
          </h2>
          {events.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.audit_empty`)}</p>
          ) : (
            <ul className="space-y-1 max-h-64 overflow-y-auto font-mono text-[11px] text-[var(--text-secondary)]">
              {events.map((ev) => (
                <li key={ev.id}>
                  {ev.created_at} · {ev.method} {ev.path} · {ev.status} · {ev.detail}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </PageShell>
  )
}
