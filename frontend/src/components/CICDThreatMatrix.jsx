/**
 * Module 8: Phantom Pipeline / CI/CD Threat Matrix.
 * Horizontal pipeline (Commit -> Build -> Test -> Deploy), red stages, modal with Attacker's Playbook.
 */
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'
import StandaloneLabShell from './ui/StandaloneLabShell'
import Button from './ui/Button'
import useFocusTrap from '../hooks/useFocusTrap'

const STAGE_KEYS = ['commit', 'build', 'test', 'deploy']

export default function CICDThreatMatrix() {
  const { t } = useTranslation()
  const NS = 'components.tools.cicdThreatMatrix'
  const { clientId } = useParams()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalFinding, setModalFinding] = useState(null)
  const [runRepoUrl, setRunRepoUrl] = useState('')
  const [running, setRunning] = useState(false)
  const [client, setClient] = useState(null)

  // Dialog a11y for the Attacker's Playbook modal: focus trap + Escape-to-close.
  const modalRef = useRef(null)
  const modalTitleId = useId()
  useFocusTrap(modalRef, !!modalFinding)
  useEffect(() => {
    if (!modalFinding) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setModalFinding(null) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [modalFinding])

  const STAGES = STAGE_KEYS.map((key) => ({
    key,
    label: t(`${NS}.stages.${key}`),
    apiName: key.charAt(0).toUpperCase() + key.slice(1),
  }))

  const fetchFindings = useCallback(() => {
    if (!clientId) return
    setLoading(true)
    apiFetch(`/api/clients/${clientId}/cicd-findings`)
      .then((data) => setFindings(data?.findings ?? []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false))
  }, [clientId])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  useEffect(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
      })
      .catch(() => setClient(null))
  }, [clientId])

  const findingsByStage = STAGES.reduce((acc, stage) => {
    acc[stage.apiName] = findings.filter((f) => (f.stage || 'Build') === stage.apiName)
    return acc
  }, {})

  const runScan = () => {
    if (!clientId || !runRepoUrl.trim()) return
    setRunning(true)
    apiFetch('/api/pipeline-scan/run', {
      method: 'POST',
      body: { client_id: clientId, repo_url: runRepoUrl.trim() },
    })
      .then(() => fetchFindings())
      .catch(() => fetchFindings())
      .finally(() => setRunning(false))
  }

  return (
    <StandaloneLabShell
      title={t(`${NS}.title`)}
      subtitle={clientId && client ? t(`${NS}.client_meta`, { name: client.name, id: clientId }) : undefined}
    >
        <div className="mb-6 flex flex-wrap gap-2">
          <input
            type="text"
            value={runRepoUrl}
            onChange={(e) => setRunRepoUrl(e.target.value)}
            placeholder={t(`${NS}.repo_placeholder`)}
            className="rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white placeholder-[var(--text-muted)] w-80"
          />
          <Button variant="unstyled"
            onClick={runScan}
            disabled={running || !clientId}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-[var(--bg-4)] text-white text-sm font-medium"
          >
            {running ? t(`${NS}.scanning`) : t(`${NS}.run_scan`)}
          </Button>
        </div>

        <div className="rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 p-6">
          <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-4">{t(`${NS}.pipeline_title`)}</h2>
          <div className="flex flex-wrap items-center justify-between gap-4">
            {STAGES.map((stage, idx) => {
              const count = (findingsByStage[stage.apiName] || []).length
              const isRed = count > 0
              return (
                <div key={stage.key} className="flex items-center gap-2">
                  <Button variant="unstyled"
                    type="button"
                    onClick={() => count > 0 && setModalFinding(findingsByStage[stage.apiName][0])}
                    title={count > 0 ? t(`${NS}.view_findings`, { count }) : ''}
                    className={`rounded-xl px-6 py-4 font-bold text-sm transition-all ${
                      isRed
                        ? 'bg-red-500/30 border-2 border-red-500 text-red-200 hover:bg-red-500/50'
                        : 'bg-[var(--bg-3)] border border-[var(--border-strong)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                    }`}
                  >
                    {stage.label}
                    {count > 0 && <span className="ml-2 text-xs">({count})</span>}
                  </Button>
                  {idx < STAGES.length - 1 && (
                    <span className="text-[var(--text-muted)]">→</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {loading && <p className="text-[var(--text-muted)] mt-4">{t(`${NS}.loading_findings`)}</p>}
        {!loading && findings.length === 0 && (
          <p className="text-[var(--text-muted)] mt-4">{t(`${NS}.no_findings`)}</p>
        )}

        {modalFinding && (
          // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions -- modal backdrop click-to-dismiss; contains interactive children
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onClick={() => setModalFinding(null)}
          >
            {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions -- stopPropagation guard on the dialog panel; Escape + close button provide the keyboard path */}
            <div
              ref={modalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby={modalTitleId}
              className="rounded-xl bg-[var(--bg-1)] border-2 border-[var(--border-strong)] max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-[var(--border-default)] flex items-center justify-between">
                <h3 id={modalTitleId} className="text-lg font-bold text-red-400">{t(`${NS}.playbook_title`)}</h3>
                <Button variant="unstyled"
                  type="button"
                  onClick={() => setModalFinding(null)}
                  className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
                >
                  ✕
                </Button>
              </div>
              <div className="p-4 text-sm text-amber-200 bg-amber-500/10 border-b border-[var(--border-default)]">
                <strong>{t(`${NS}.blast_radius`)}</strong> {modalFinding.blast_radius || '—'}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-6 overflow-auto flex-1">
                <div>
                  <div className="text-[var(--text-tertiary)] text-xs uppercase mb-2">{t(`${NS}.vulnerable_code`, { path: modalFinding.file_path })}</div>
                  <pre className="rounded-lg bg-[var(--bg-0)] p-4 text-[var(--text-secondary)] text-xs overflow-x-auto whitespace-pre-wrap border border-[var(--border-default)]">
                    {modalFinding.vulnerable_snippet || '—'}
                  </pre>
                </div>
                <div>
                  <div className="text-[var(--text-tertiary)] text-xs uppercase mb-2">{t(`${NS}.poc_code`)}</div>
                  <pre className="rounded-lg bg-[var(--bg-0)] p-4 text-red-200/90 text-xs overflow-x-auto whitespace-pre-wrap border border-red-900/50">
                    {modalFinding.poc_exploit || '—'}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
    </StandaloneLabShell>
  )
}
