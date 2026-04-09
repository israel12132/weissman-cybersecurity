import React, { useState } from 'react'
import CeoWarRoomStream from '../components/ceo/CeoWarRoomStream'
import CeoGenesisPanel from '../components/ceo/CeoGenesisPanel'
import CeoVaccineVault from '../components/ceo/CeoVaccineVault'
import CeoSovereignLab from '../components/ceo/CeoSovereignLab'

export default function CeoCommandCenter() {
  const [jobId, setJobId] = useState('')

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
            <h1 className="text-lg font-bold tracking-tight text-white">CEO command center</h1>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mt-1">
              Live APIs · RBAC enforced server-side
            </p>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 space-y-10">
        <section>
          <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-red-400/90 mb-3">War room stream</h2>
          <CeoWarRoomStream jobId={jobId} onJobIdChange={setJobId} />
        </section>

        <section>
          <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-emerald-400/90 mb-3">
            Genesis and HPC
          </h2>
          <CeoGenesisPanel />
        </section>

        <section className="grid gap-10 lg:grid-cols-1">
          <div>
            <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-400/90 mb-3">Vaccine vault</h2>
            <CeoVaccineVault />
          </div>
          <div>
            <h2 className="text-xs font-mono uppercase tracking-[0.2em] text-violet-400/90 mb-3">Sovereign lab</h2>
            <CeoSovereignLab />
          </div>
        </section>
      </main>
    </div>
  )
}
