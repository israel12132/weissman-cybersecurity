import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Outlet, useLocation, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/cockpit/ProtectedRoute'
import RouteErrorBoundary from './components/RouteErrorBoundary'

/** Catches render errors above per-route boundaries (e.g. provider / layout bugs). */
class RootErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    if (import.meta.env.DEV) {
      console.error('[RootErrorBoundary]', error, info?.componentStack)
    }
  }

  render() {
    if (this.state.error) {
      const msg = this.state.error?.message || 'Application error'
      return (
        <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-200 p-8 font-mono">
          <h1 className="text-lg font-semibold text-red-400 mb-2">Command Center failed to load</h1>
          <p className="text-sm text-slate-400 mb-6 max-w-lg text-center break-words">{msg}</p>
          <button
            type="button"
            className="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10"
            onClick={() => window.location.reload()}
          >
            Reload page
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
import Login from './components/cockpit/Login'
import Cockpit from './Cockpit'
import SystemCore from './components/SystemCore'
import ReportView from './components/ReportView'
import AttackSurfaceGraph from './components/AttackSurfaceGraph'
import SemanticLogicEngine from './components/SemanticLogicEngine'
import QuantumTimingProfiler from './components/QuantumTimingProfiler'
import AIRedteamArena from './components/AIRedteamArena'
import ZeroDayRadar from './components/ZeroDayRadar'
import CICDThreatMatrix from './components/CICDThreatMatrix'
import MemoryForensicsLab from './components/MemoryForensicsLab'
import AttackChainView from './components/cockpit/AttackChainView'
import CeoProtectedRoute from './components/ceo/CeoProtectedRoute'
// ── New enterprise pages ──────────────────────────────────────────────────────
import EngineMatrix from './pages/EngineMatrix'
import EngineDetail from './pages/EngineDetail'
import ThreatEmulation from './pages/ThreatEmulation'
import SupplyChainHub from './pages/SupplyChainHub'
import NetworkIntelligence from './pages/NetworkIntelligence'
import CloudControlTower from './pages/CloudControlTower'
import PqcRadar from './pages/PqcRadar'
import OastDashboard from './pages/OastDashboard'
import CouncilHitlQueue from './pages/CouncilHitlQueue'
import SsoDashboard from './pages/SsoDashboard'
import DigitalTwinSimulator from './pages/DigitalTwinSimulator'
import FindingsCommandCenter from './pages/FindingsCommandCenter'
import AdminManagement from './pages/AdminManagement'
import DomainDiscovery from './pages/DomainDiscovery'
import ThreatIntelHub from './pages/ThreatIntelHub'
import IncidentResponseCenter from './pages/IncidentResponseCenter'
import VulnIntelDashboard from './pages/VulnIntelDashboard'
import DarkWebMonitor from './pages/DarkWebMonitor'
import ThreatHuntingWorkbench from './pages/ThreatHuntingWorkbench'
import EngineClientCatalog from './pages/EngineClientCatalog'
// ── New UI improvements ──────────────────────────────────────────────────────
import RateLimitAnalytics from './pages/RateLimitAnalytics'
import MobileSecurity from './pages/MobileSecurity'
import OtIcsSecurity from './pages/OtIcsSecurity'
import NetworkProtocols from './pages/NetworkProtocols'
import SocialEngineering from './pages/SocialEngineering'
import RemediationHub from './pages/RemediationHub'
import EngineManagementConsole from './pages/EngineManagementConsole'
import SystemConfiguration from './pages/SystemConfiguration'
import MetricsDashboard from './pages/MetricsDashboard'
import CeoVault from './pages/CeoVault'
import RiskGraphVisualization from './pages/RiskGraphVisualization'
import ComplianceFrameworks from './pages/ComplianceFrameworks'
import SBOMBrowser from './pages/SBOMBrowser'
import IntegrationManager from './pages/IntegrationManager'
import AlertRulesEngine from './pages/AlertRulesEngine'
import ScanScheduler from './pages/ScanScheduler'
import ContainmentRulesBuilder from './pages/ContainmentRulesBuilder'
import BaselineAndDrift from './pages/BaselineAndDrift'
import IdentityContextManager from './pages/IdentityContextManager'
// ──────────────────────────────────────────────────────────────────────────────
import App from './App'
import './index.css'

function ProtectedOutlet() {
  const location = useLocation()
  return (
    <RouteErrorBoundary key={location.pathname}>
      <Outlet />
    </RouteErrorBoundary>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RootErrorBoundary>
    <BrowserRouter basename="/command-center">
      <AuthProvider>
        <Routes>
          <Route path="login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><ProtectedOutlet /></ProtectedRoute>}>
            <Route
              index
              element={
                <CeoProtectedRoute>
                  <Cockpit ceoIntegrated />
                </CeoProtectedRoute>
              }
            />
            <Route path="operations" element={<Cockpit />} />
            <Route path="system-core" element={<SystemCore />} />
            <Route path="report/:clientId" element={<ReportView />} />
            <Route path="attack-surface-graph/:clientId" element={<AttackSurfaceGraph />} />
            <Route path="semantic-logic/:clientId" element={<SemanticLogicEngine />} />
            <Route path="timing-profiler" element={<QuantumTimingProfiler />} />
            <Route path="timing-profiler/:clientId" element={<QuantumTimingProfiler />} />
            <Route path="ai-arena" element={<AIRedteamArena />} />
            <Route path="ai-arena/:clientId" element={<AIRedteamArena />} />
            <Route path="zero-day-radar" element={<ZeroDayRadar />} />
            <Route path="cicd-matrix/:clientId" element={<CICDThreatMatrix />} />
            <Route path="memory-lab/:clientId" element={<MemoryForensicsLab />} />
            <Route path="attack-chain/:clientId" element={<AttackChainView />} />
            {/* ── Enterprise C2 pages ─────────────────────────────────────────── */}
            <Route path="engines" element={<EngineMatrix />} />
            <Route path="engines/:engineId" element={<EngineDetail />} />
            <Route path="domain-discovery" element={<DomainDiscovery />} />
            <Route path="threat-emulation" element={<ThreatEmulation />} />
            <Route path="supply-chain" element={<SupplyChainHub />} />
            <Route path="network" element={<NetworkIntelligence />} />
            <Route path="cloud" element={<CloudControlTower />} />
            <Route path="pqc-radar" element={<PqcRadar />} />
            <Route path="oast" element={<OastDashboard />} />
            <Route path="council-queue" element={<CouncilHitlQueue />} />
            <Route path="sso-config" element={<SsoDashboard />} />
            <Route path="digital-twin" element={<DigitalTwinSimulator />} />
            <Route path="digital-twin/:clientId" element={<DigitalTwinSimulator />} />
            <Route path="findings" element={<FindingsCommandCenter />} />
            <Route path="threat-intel" element={<ThreatIntelHub />} />
            <Route path="intel-map" element={<App />} />
            <Route path="incident-response" element={<IncidentResponseCenter />} />
            <Route path="vuln-intel" element={<VulnIntelDashboard />} />
            <Route path="dark-web" element={<DarkWebMonitor />} />
            <Route path="threat-hunting" element={<ThreatHuntingWorkbench />} />
            <Route path="engine-catalog" element={<EngineClientCatalog />} />
            <Route path="admin" element={<AdminManagement />} />
            {/* ── New UI improvements routes ──────────────────────────────────── */}
            <Route path="rate-limits" element={<RateLimitAnalytics />} />
            <Route path="mobile-security" element={<MobileSecurity />} />
            <Route path="ot-ics" element={<OtIcsSecurity />} />
            <Route path="network-protocols" element={<NetworkProtocols />} />
            <Route path="social-engineering" element={<SocialEngineering />} />
            <Route path="remediation" element={<RemediationHub />} />
            <Route path="engine-management" element={<EngineManagementConsole />} />
            <Route path="system-config" element={<SystemConfiguration />} />
            <Route path="metrics" element={<MetricsDashboard />} />
            <Route path="ceo-vault" element={<CeoVault />} />
            <Route path="risk-graph" element={<RiskGraphVisualization />} />
            <Route path="compliance" element={<ComplianceFrameworks />} />
            <Route path="sbom" element={<SBOMBrowser />} />
            <Route path="integrations" element={<IntegrationManager />} />
            <Route path="alert-rules" element={<AlertRulesEngine />} />
            <Route path="scan-scheduler" element={<ScanScheduler />} />
            <Route path="containment-rules" element={<ContainmentRulesBuilder />} />
            <Route path="baseline-drift" element={<BaselineAndDrift />} />
            <Route path="identity-context" element={<IdentityContextManager />} />
            {/* ─────────────────────────────────────────────────────────────────── */}
            <Route path="ceo" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
    </RootErrorBoundary>
  </React.StrictMode>,
)
