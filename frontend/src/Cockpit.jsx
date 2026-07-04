import React from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from './context/ClientContext'
import GlobalNexus from './components/cockpit/GlobalNexus'
import ClientCockpit from './components/cockpit/ClientCockpit'
import TargetScopePanel from './components/cockpit/TargetScopePanel'
import ToastContainer from './components/cockpit/Toast'
import ExecKpiStrip from './components/cockpit/ExecKpiStrip'
import OnboardingWizard from './components/onboarding/OnboardingWizard'
import GlobalSearch from './components/GlobalSearch'
import EvidenceNotice from './components/ui/EvidenceNotice'

function CockpitEvidenceStrip() {
  const { t } = useTranslation()
  return (
    <div className="shrink-0 border-b border-white/[0.06] bg-black/45 px-3 py-1.5">
      <EvidenceNotice className="rounded-lg border-cyan-500/15 bg-cyan-500/[0.03] px-3 py-2 text-[10px] leading-snug">
        {t('pages.cockpit.evidence_notice')}
      </EvidenceNotice>
    </div>
  )
}

function CockpitLayout({ ceoIntegrated }) {
  const { clients, refreshClients, setSelectedClientId } = useClient()
  const showOnboarding = clients.length === 0

  const handleOnboardingComplete = async ({ clientId }) => {
    if (clientId) setSelectedClientId(String(clientId))
    await refreshClients()
  }

  return (
    <>
          {/* Top-level layout: KPI strip is a sticky hero band over the original
              3-column cockpit. Strip uses real-time aggregated data and is visible
              regardless of which tab the user picks below.  */}
          <div className="relative flex flex-col h-[100dvh] max-h-[100dvh] w-full max-w-[100vw] min-h-0 overflow-hidden bg-[#030508]">
            {/* Multi-layer depth background */}
            <div
              className="pointer-events-none absolute inset-0"
              aria-hidden
              style={{
                background: [
                  'radial-gradient(ellipse 90% 60% at 15% -10%, rgba(34,211,238,0.07) 0%, transparent 55%)',
                  'radial-gradient(ellipse 70% 50% at 85% 5%, rgba(99,102,241,0.05) 0%, transparent 50%)',
                  'radial-gradient(ellipse 120% 80% at 50% 100%, rgba(15,23,42,0.9) 0%, transparent 60%)',
                  'linear-gradient(180deg, #0c1220 0%, #070b14 42%, #04060c 100%)',
                ].join(', '),
              }}
            />
            <div
              className="pointer-events-none absolute inset-0 opacity-[0.015]"
              aria-hidden
              style={{
                backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 1px, rgba(255,255,255,0.4) 1px, rgba(255,255,255,0.4) 2px)',
              }}
            />
            <div className="relative z-[1] flex flex-col h-full min-h-0">
            <ExecKpiStrip />
            <CockpitEvidenceStrip />
            <div className="flex flex-col lg:flex-row flex-1 min-h-0 overflow-hidden">
              <GlobalNexus ceoIntegrated={ceoIntegrated} />
              <div id="main-content" className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden" tabIndex={-1}>
              <ClientCockpit ceoIntegrated={ceoIntegrated} />
              </div>
              <TargetScopePanel ceoIntegrated={ceoIntegrated} />
            </div>
            </div>
          </div>
          <ToastContainer />
          <GlobalSearch />
          <OnboardingWizard open={showOnboarding} onComplete={handleOnboardingComplete} />
    </>
  )
}

export default function Cockpit({ ceoIntegrated = false }) {
  return <CockpitLayout ceoIntegrated={ceoIntegrated} />
}
