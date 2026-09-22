import { useTranslation } from 'react-i18next'
import { useClient } from './context/ClientContext'
import GlobalNexus from './components/cockpit/GlobalNexus'
import ClientCockpit from './components/cockpit/ClientCockpit'
import TargetScopePanel from './components/cockpit/TargetScopePanel'
import ToastContainer from './components/cockpit/Toast'
import CommandHero from './components/cockpit/CommandHero'
import OnboardingWizard from './components/onboarding/OnboardingWizard'
import EvidenceNotice from './components/ui/EvidenceNotice'

function CockpitEvidenceStrip() {
  const { t } = useTranslation()
  return (
    <div className="shrink-0 border-b border-[var(--border-subtle)] bg-[var(--table-surface)] px-3 py-1.5">
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
          {/* Command center: a premium hero command deck (real-time aggregate
              posture) crowns the 3-column operational cockpit below it. */}
          <div className="relative flex flex-col h-[100dvh] max-h-[100dvh] w-full max-w-[100vw] min-h-0 overflow-hidden bg-[var(--bg-0)]">
            {/* Multi-layer depth background — theme-aware via --cockpit-bg. */}
            <div
              className="pointer-events-none absolute inset-0"
              aria-hidden
              style={{ background: 'var(--cockpit-bg)' }}
            />
            {/* Soft brand aurora — replaces the old harsh scanline for a cleaner,
                more premium depth. */}
            <div
              className="pointer-events-none absolute inset-x-0 top-0 h-[42vh]"
              aria-hidden
              style={{
                background:
                  'radial-gradient(120% 80% at 22% 0%, color-mix(in srgb, var(--brand-primary) 12%, transparent) 0%, transparent 60%), radial-gradient(120% 80% at 85% 0%, color-mix(in srgb, var(--brand-secondary) 10%, transparent) 0%, transparent 55%)',
              }}
            />
            <div className="relative z-[1] flex flex-col h-full min-h-0">
            <CommandHero />
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
          <OnboardingWizard open={showOnboarding} onComplete={handleOnboardingComplete} />
    </>
  )
}

export default function Cockpit({ ceoIntegrated = false }) {
  return <CockpitLayout ceoIntegrated={ceoIntegrated} />
}
