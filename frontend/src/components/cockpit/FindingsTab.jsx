import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { createColumnHelper } from '@tanstack/react-table'
import { useClient } from '../../context/ClientContext'
import DigitalEvidenceHUD from '../warroom/DigitalEvidenceHUD'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import FindingVerifyButton, { LiveVerdictBadge, findingVerifyId } from '../findings/FindingLiveVerify'
import { apiFetch } from '../../utils/apiFetch'
import { liveCvssLabel } from '../../lib/liveFindingIntel'
import ClientReportDownloadBar from '../ClientReportDownloadBar'
import SeverityBadge from '../ui/SeverityBadge'
import DataTable from '../ui/DataTable'

const columnHelper = createColumnHelper()
const FT = 'components.cockpitTabs.findings'

export default function FindingsTab() {
  const { t } = useTranslation()
  const { selectedClientId, selectedClient } = useClient()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)
  const [findingsError, setFindingsError] = useState(null)
  const [evidenceFinding, setEvidenceFinding] = useState(null)

  const handleVerifyComplete = useCallback((rawId, verification) => {
    const patch = (f) => (
      findingVerifyId(f) === String(rawId)
        ? { ...f, live_verification: verification, live_verdict: verification?.verdict }
        : f
    )
    setFindings((prev) => prev.map(patch))
    setEvidenceFinding((prev) => {
      if (!prev) return prev
      if (findingVerifyId(prev) !== String(rawId)) return prev
      return { ...prev, live_verification: verification, live_verdict: verification?.verdict }
    })
  }, [])

  const columns = useMemo(
    () => [
      columnHelper.accessor('severity', {
        header: t(`${FT}.table.severity`),
        cell: (info) => <SeverityBadge severity={info.getValue()} size="sm" />,
      }),
      columnHelper.accessor((f) => liveCvssLabel(f), {
        id: 'cvss',
        header: t(`${FT}.table.cvss`),
        cell: (info) => <span className="text-[#9ca3af] font-mono text-xs">{info.getValue()}</span>,
      }),
      columnHelper.accessor((f) => sanitizeFindingPlainText(f.title, 2000), {
        id: 'title',
        header: t(`${FT}.table.title`),
        cell: (info) => (
          <span className="text-white max-w-md truncate block" title={info.getValue()}>
            {info.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor('source', {
        header: t(`${FT}.table.engine_source`),
        cell: (info) => (
          <span className="text-[#22d3ee] font-mono text-xs">{info.getValue() || '—'}</span>
        ),
      }),
      columnHelper.display({
        id: 'live_verify',
        header: t('findings.col_live_verify'),
        // Interactive controls: stop row-click (which opens the evidence drawer) from firing.
        cell: ({ row }) => (
          <div
            className="flex items-center gap-1.5"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => e.stopPropagation()}
            role="presentation"
          >
            <LiveVerdictBadge
              verification={row.original.live_verification}
              verdict={row.original.live_verdict}
              compact
            />
            <FindingVerifyButton compact finding={row.original} onVerified={handleVerifyComplete} />
          </div>
        ),
      }),
    ],
    [t, handleVerifyComplete],
  )

  const fetchFindings = useCallback(async () => {
    if (!selectedClientId) {
      setFindings([])
      setFindingsError(null)
      return
    }
    setLoading(true)
    setFindingsError(null)
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/findings`)
      setFindings(Array.isArray(d.findings) ? d.findings : [])
      if (!Array.isArray(d.findings)) {
        setFindingsError(t('components.cockpitTabs.findings.unexpected_response'))
      }
    } catch (e) {
      setFindings([])
      setFindingsError(
        e?.response
          ? await formatApiErrorResponse(e.response)
          : e?.message || t('components.cockpitTabs.findings.network_error'),
      )
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">{t('components.cockpitTabs.findings.select_client')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-6">
      {findingsError && (
        <div
          className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200"
          role="alert"
        >
          {findingsError}
        </div>
      )}
      {/* Top: PDF/Excel + Attack Chain */}
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <ClientReportDownloadBar clientId={selectedClientId} className="flex-1" />
        {selectedClientId && (
          <Link
            to={`/attack-chain/${selectedClientId}`}
            className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-all duration-300 self-end"
          >
            {t('components.cockpitTabs.findings.view_attack_chain')}
          </Link>
        )}
      </div>

      {/* Table */}
      <DataTable
        id="cockpit-findings-table"
        columns={columns}
        data={findings}
        loading={loading}
        getRowId={(f) => f.id}
        onRowClick={(row) => setEvidenceFinding(row.original)}
        animateRows={false}
        emptyState={
          findingsError ? undefined : {
            icon: 'search-x',
            title: t(`${FT}.empty.title`),
            body: t(`${FT}.empty.body`),
            compact: true,
          }
        }
      />

      <DigitalEvidenceHUD
        clientId={selectedClientId}
        finding={evidenceFinding}
        onClose={() => setEvidenceFinding(null)}
        onVerified={handleVerifyComplete}
      />
    </div>
  )
}
