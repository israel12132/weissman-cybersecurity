import React, { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import CeoWarRoomStream from '../components/ceo/CeoWarRoomStream'
import CeoGenesisPanel from '../components/ceo/CeoGenesisPanel'
import CeoVaccineVault from '../components/ceo/CeoVaccineVault'
import CeoSovereignLab from '../components/ceo/CeoSovereignLab'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { SkeletonBar } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'

export default function CeoCommandCenter() {
  const { t } = useTranslation()
  const [jobId, setJobId] = useState('')
  const [booting, setBooting] = useState(true)
  const [sectionSearch, setSectionSearch] = useState('')
  const [exporting, setExporting] = useState(false)

  const handleExport = useCallback(async () => {
    setExporting(true)
    try {
      const [telemetry, snapshot, buffer, vault] = await Promise.all([
        apiFetch('/api/ceo/telemetry').then((r) => (r.ok ? r.json() : null)),
        apiFetch('/api/ceo/god-mode/snapshot').then((r) => (r.ok ? r.json() : null)),
        apiFetch('/api/ceo/sovereign/buffer?limit=200').then((r) => (r.ok ? r.json() : null)),
        apiFetch('/api/ceo/vault?limit=100&offset=0').then((r) => (r.ok ? r.json() : null)),
      ])
      const bundle = {
        exported_at: new Date().toISOString(),
        telemetry,
        god_mode_snapshot: snapshot,
        sovereign_buffer: buffer,
        vaccine_vault: vault,
      }
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `weissman-ceo-export-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setExporting(false)
    }
  }, [])

  useEffect(() => {
    const id = window.requestAnimationFrame(() => setBooting(false))
    return () => window.cancelAnimationFrame(id)
  }, [])

  const q = sectionSearch.trim().toLowerCase()
  const showWarRoom = !q || q.includes('war') || q.includes('job') || q.includes('stream') || (jobId && jobId.toLowerCase().includes(q))
  const showGenesis = !q || q.includes('genesis') || q.includes('hpc')
  const showVault = !q || q.includes('vaccine') || q.includes('vault')
  const showLab = !q || q.includes('sovereign') || q.includes('lab')

  return (
    <div
      className="min-h-screen text-slate-100"
      style={{
        background: 'radial-gradient(ellipse 100% 80% at 50% 0%, #0f172a 0%, #020617 55%, #000 100%)',
      }}
    >
      <header className="border-b border-white/10 bg-black/30 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">{t('pages.ceoCommandCenter.title')}</h1>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mt-1">
              {t('pages.ceoCommandCenter.subtitle')}
            </p>
          </div>
          <ShellScanActions
            onRefresh={() => window.location.reload()}
            onExport={handleExport}
            exportDisabled={exporting}
          />
          <Link
            to="/supreme-nerve-center"
            className="text-[11px] font-mono px-2.5 py-1.5 rounded-lg border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/10 transition-colors"
          >
            {t('pages.ceoCommandCenter.nerve_center_link')}
          </Link>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 space-y-10">
        <EvidenceNotice>{t('pages.ceoCommandCenter.evidence_notice')}</EvidenceNotice>

        <WeissmanListToolbar
          searchQuery={sectionSearch}
          onSearchChange={setSectionSearch}
          searchPlaceholder={t('pages.ceoCommandCenter.search_placeholder')}
        />

        {booting ? (
          <div className="space-y-4" aria-busy="true" aria-label={t('pages.ceoCommandCenter.loading')}>
            <SkeletonBar className="h-32" />
            <SkeletonBar className="h-48" />
            <SkeletonBar className="h-40" />
          </div>
        ) : (
          <>
            {showWarRoom && (
            <section>
              <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-red-400/90 mb-3">
                {t('pages.ceoCommandCenter.war_room')}
              </h2>
              <CeoWarRoomStream jobId={jobId} onJobIdChange={setJobId} />
            </section>
            )}

            {showGenesis && (
            <section>
              <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-emerald-400/90 mb-3">
                {t('pages.ceoCommandCenter.genesis_hpc')}
              </h2>
              <CeoGenesisPanel />
            </section>
            )}

            {(showVault || showLab) && (
            <section className="grid gap-10 lg:grid-cols-1">
              {showVault && (
              <div>
                <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-400/90 mb-3">
                  {t('pages.ceoCommandCenter.vaccine_vault')}
                </h2>
                <CeoVaccineVault />
              </div>
              )}
              {showLab && (
              <div>
                <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-violet-400/90 mb-3">
                  {t('pages.ceoCommandCenter.sovereign_lab')}
                </h2>
                <CeoSovereignLab />
              </div>
              )}
            </section>
            )}
            {!showWarRoom && !showGenesis && !showVault && !showLab && q && (
              <p className="text-sm font-mono text-white/40 text-center py-8">{t('weissmanFindings.filtered_title')}</p>
            )}
          </>
        )}
      </main>
    </div>
  )
}
