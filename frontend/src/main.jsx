import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Outlet, useLocation } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/cockpit/ProtectedRoute'
import RouteErrorBoundary from './components/RouteErrorBoundary'
import './i18n' // bootstrap i18next before any component renders
import i18n from './i18n'
import { ToastProvider } from './components/ui/Toaster'
import RateLimitProvider from './components/RateLimitProvider'
import KeyboardShortcuts from './components/ui/KeyboardShortcuts'
import SkipToContent from './components/ui/SkipToContent'
import NotFound from './components/ui/NotFound'
import RouteLoader from './components/ui/RouteLoader'

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
      const msg = this.state.error?.message || i18n.t('errors.application_error')
      return (
        <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-200 p-8 font-mono">
          <h1 className="text-lg font-semibold text-red-400 mb-2">{i18n.t('errors.app_load_failed')}</h1>
          <p className="text-sm text-slate-400 mb-6 max-w-lg text-center break-words">{msg}</p>
          <button
            type="button"
            className="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10"
            onClick={() => window.location.reload()}
          >
            {i18n.t('errors.reload_page')}
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
// Eagerly loaded — needed for first paint or for the route guards above the Suspense boundary.
import Login from './components/cockpit/Login'
import Cockpit from './Cockpit'
import CeoProtectedRoute from './components/ceo/CeoProtectedRoute'

// Everything else is route-lazy so the initial bundle stays ≈400 KB. React.Suspense renders a
// branded loader until the chunk arrives.
const SystemCore = React.lazy(() => import('./components/SystemCore'))
const ReportView = React.lazy(() => import('./components/ReportView'))
const AttackSurfaceGraph = React.lazy(() => import('./components/AttackSurfaceGraph'))
const SemanticLogicEngine = React.lazy(() => import('./components/SemanticLogicEngine'))
const QuantumTimingProfiler = React.lazy(() => import('./components/QuantumTimingProfiler'))
const AIRedteamArena = React.lazy(() => import('./components/AIRedteamArena'))
const ZeroDayRadar = React.lazy(() => import('./components/ZeroDayRadar'))
const CICDThreatMatrix = React.lazy(() => import('./components/CICDThreatMatrix'))
const MemoryForensicsLab = React.lazy(() => import('./components/MemoryForensicsLab'))
const AttackChainView = React.lazy(() => import('./components/cockpit/AttackChainView'))
const EngineMatrix = React.lazy(() => import('./pages/EngineMatrix'))
const EngineDetail = React.lazy(() => import('./pages/EngineDetail'))
const OsintEngineProfile = React.lazy(() => import('./pages/OsintEngineProfile'))
const TopTierEngineHub = React.lazy(() => import('./pages/TopTierEngineHub'))
const TopTierEngineProfile = React.lazy(() => import('./pages/TopTierEngineProfile'))
const StrategicEngineProgram = React.lazy(() => import('./pages/StrategicEngineProgram'))
const BusinessEngineProfile = React.lazy(() => import('./pages/BusinessEngineProfile'))
const ThreatEmulation = React.lazy(() => import('./pages/ThreatEmulation'))
const SupplyChainHub = React.lazy(() => import('./pages/SupplyChainHub'))
const NetworkIntelligence = React.lazy(() => import('./pages/NetworkIntelligence'))
const CloudControlTower = React.lazy(() => import('./pages/CloudControlTower'))
const CloudPostureCommandCenter = React.lazy(() => import('./pages/CloudPostureCommandCenter'))
const IacSecurityCenter = React.lazy(() => import('./pages/IacSecurityCenter'))
const AttackSurfaceManagement = React.lazy(() => import('./pages/AttackSurfaceManagement'))
const DnsDomainPosture = React.lazy(() => import('./pages/DnsDomainPosture'))
const WebCachePosture = React.lazy(() => import('./pages/WebCachePosture'))
const TransportSecurityCommandCenter = React.lazy(() => import('./pages/TransportSecurityCommandCenter'))
const HttpSmugglingPosture = React.lazy(() => import('./pages/HttpSmugglingPosture'))
const PkiTlsCommandCenter = React.lazy(() => import('./pages/PkiTlsCommandCenter'))
const EmailDnsPosture = React.lazy(() => import('./pages/EmailDnsPosture'))
const PqcRadar = React.lazy(() => import('./pages/PqcRadar'))
const EdDetectionSurface = React.lazy(() => import('./pages/EdDetectionSurface'))
const WafBypassLab = React.lazy(() => import('./pages/WafBypassLab'))
const WebSocketSecurityCommandCenter = React.lazy(() => import('./pages/WebSocketSecurityCommandCenter'))
const JwtAttackLab = React.lazy(() => import('./pages/JwtAttackLab'))
const FileUploadSecurityLab = React.lazy(() => import('./pages/FileUploadSecurityLab'))
const OastDashboard = React.lazy(() => import('./pages/OastDashboard'))
const OobVerification = React.lazy(() => import('./pages/OobVerification'))
const TemplateEngineWorkbench = React.lazy(() => import('./pages/TemplateEngineWorkbench'))
const AstFuzzingStudio = React.lazy(() => import('./pages/AstFuzzingStudio'))
const FeedbackLoopVerification = React.lazy(() => import('./pages/FeedbackLoopVerification'))
const CouncilHitlQueue = React.lazy(() => import('./pages/CouncilHitlQueue'))
const RoeApprovals = React.lazy(() => import('./pages/RoeApprovals'))
const SsoDashboard = React.lazy(() => import('./pages/SsoDashboard'))
const NexusSovereignSwarm = React.lazy(() => import('./pages/NexusSovereignSwarm'))
const GraphqlSecurityCommandCenter = React.lazy(() => import('./pages/GraphqlSecurityCommandCenter'))
const CicdPipelineSecurityCommandCenter = React.lazy(() => import('./pages/CicdPipelineSecurityCommandCenter'))
const ServerlessSecurityCommandCenter = React.lazy(() => import('./pages/ServerlessSecurityCommandCenter'))
const DigitalTwinSimulator = React.lazy(() => import('./pages/DigitalTwinSimulator'))
const FindingsCommandCenter = React.lazy(() => import('./pages/FindingsCommandCenter'))
const AdminManagement = React.lazy(() => import('./pages/AdminManagement'))
const DomainDiscovery = React.lazy(() => import('./pages/DomainDiscovery'))
const ThreatIntelHub = React.lazy(() => import('./pages/ThreatIntelHub'))
const IncidentResponseCenter = React.lazy(() => import('./pages/IncidentResponseCenter'))
const VulnIntelDashboard = React.lazy(() => import('./pages/VulnIntelDashboard.jsx'))
const AgentManagement = React.lazy(() => import('./pages/AgentManagement'))
const DarkWebMonitor = React.lazy(() => import('./pages/DarkWebMonitor'))
const ThreatHuntingWorkbench = React.lazy(() => import('./pages/ThreatHuntingWorkbench'))
const ThreatAnalysisCenter = React.lazy(() => import('./pages/ThreatAnalysisCenter'))
const EngineClientCatalog = React.lazy(() => import('./pages/EngineClientCatalog'))
const RateLimitAnalytics = React.lazy(() => import('./pages/RateLimitAnalytics'))
const MobileSecurity = React.lazy(() => import('./pages/MobileSecurity'))
const OtIcsSecurity = React.lazy(() => import('./pages/OtIcsSecurity'))
const NetworkProtocols = React.lazy(() => import('./pages/NetworkProtocols'))
const SocialEngineering = React.lazy(() => import('./pages/SocialEngineering'))
const RemediationHub = React.lazy(() => import('./pages/RemediationHub'))
const EngineManagementConsole = React.lazy(() => import('./pages/EngineManagementConsole'))
const EngineReliability = React.lazy(() => import('./pages/EngineReliability'))
const SystemConfiguration = React.lazy(() => import('./pages/SystemConfiguration'))
const MetricsDashboard = React.lazy(() => import('./pages/MetricsDashboard'))
const CeoVault = React.lazy(() => import('./pages/CeoVault'))
const CeoCommandCenter = React.lazy(() => import('./pages/CeoCommandCenter'))
const RiskGraphVisualization = React.lazy(() => import('./pages/RiskGraphVisualization'))
const ComplianceFrameworks = React.lazy(() => import('./pages/ComplianceFrameworks'))
const SBOMBrowser = React.lazy(() => import('./pages/SBOMBrowser'))
const IntegrationManager = React.lazy(() => import('./pages/IntegrationManager'))
const AlertRulesEngine = React.lazy(() => import('./pages/AlertRulesEngine'))
const ScanScheduler = React.lazy(() => import('./pages/ScanScheduler'))
const ContainmentRulesBuilder = React.lazy(() => import('./pages/ContainmentRulesBuilder'))
const BaselineAndDrift = React.lazy(() => import('./pages/BaselineAndDrift'))
const IdentityContextManager = React.lazy(() => import('./pages/IdentityContextManager'))
const IdentitySecurityCenter = React.lazy(() => import('./pages/IdentitySecurityCenter'))
const KerberosSecurityCommandCenter = React.lazy(() => import('./pages/KerberosSecurityCommandCenter'))
const SmbNetbiosCommandCenter = React.lazy(() => import('./pages/SmbNetbiosCommandCenter'))
const PasswordSprayCommandCenter = React.lazy(() => import('./pages/PasswordSprayCommandCenter'))
const SamlSecurityCommandCenter = React.lazy(() => import('./pages/SamlSecurityCommandCenter'))
const KillChainOrchestrator = React.lazy(() => import('./pages/KillChainOrchestrator'))
const AIAnalysisEngine = React.lazy(() => import('./pages/AIAnalysisEngine'))
const ExploitResearchLab = React.lazy(() => import('./pages/ExploitResearchLab'))
const Clients = React.lazy(() => import('./pages/Clients'))
const ClientNew = React.lazy(() => import('./pages/ClientNew'))
const ClientDetail = React.lazy(() => import('./pages/ClientDetail'))
const ClientEngagements = React.lazy(() => import('./pages/ClientEngagements'))
const ClientEvidenceVault = React.lazy(() => import('./pages/ClientEvidenceVault'))
const ClientSaasIdpDiscovery = React.lazy(() => import('./pages/ClientSaasIdpDiscovery'))
const JobsDashboard = React.lazy(() => import('./pages/JobsDashboard'))
const StatusPage = React.lazy(() => import('./pages/StatusPage'))
const AuditLog = React.lazy(() => import('./pages/AuditLog'))
const PlaybookBuilder = React.lazy(() => import('./pages/PlaybookBuilder'))
const AskWeissman = React.lazy(() => import('./pages/AskWeissman'))
const Billing = React.lazy(() => import('./pages/Billing'))
const App = React.lazy(() => import('./App'))
import './index.css'

function ProtectedOutlet() {
  const location = useLocation()
  return (
    <RouteErrorBoundary key={location.pathname}>
      <React.Suspense fallback={<RouteLoader />}>
        <Outlet />
      </React.Suspense>
    </RouteErrorBoundary>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RootErrorBoundary>
    <BrowserRouter basename="/command-center">
      <AuthProvider>
        <ToastProvider>
        <RateLimitProvider>
        <SkipToContent />
        <KeyboardShortcuts />
        <Routes>
          <Route path="login" element={<Login />} />
          <Route
            path="status"
            element={
              <React.Suspense fallback={<RouteLoader />}>
                <StatusPage />
              </React.Suspense>
            }
          />
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
            <Route path="engines/osint" element={<OsintEngineProfile />} />
            <Route path="engines/top-tier" element={<TopTierEngineHub />} />
            <Route path="engines/top-tier/:engineId" element={<TopTierEngineProfile />} />
            <Route path="engines/strategic" element={<StrategicEngineProgram />} />
            <Route path="engines/business/:engineId" element={<BusinessEngineProfile />} />
            <Route path="engines/:engineId" element={<EngineDetail />} />
            <Route path="domain-discovery" element={<DomainDiscovery />} />
            <Route path="threat-emulation" element={<ThreatEmulation />} />
            <Route path="supply-chain" element={<SupplyChainHub />} />
            <Route path="network" element={<NetworkIntelligence />} />
            <Route path="cloud" element={<CloudControlTower />} />
            <Route path="cloud-posture" element={<CloudPostureCommandCenter />} />
            <Route path="iac-security" element={<IacSecurityCenter />} />
            <Route path="attack-surface" element={<AttackSurfaceManagement />} />
            <Route path="dns-posture" element={<DnsDomainPosture />} />
            <Route path="cache-posture" element={<WebCachePosture />} />
            <Route path="http-smuggling" element={<HttpSmugglingPosture />} />
            <Route path="transport-security" element={<TransportSecurityCommandCenter />} />
            <Route path="tls-posture" element={<PkiTlsCommandCenter />} />
            <Route path="email-posture" element={<EmailDnsPosture />} />
            <Route path="pqc-radar" element={<PqcRadar />} />
            <Route path="detection-surface" element={<EdDetectionSurface />} />
            <Route path="waf-bypass" element={<WafBypassLab />} />
            <Route path="websocket-security" element={<WebSocketSecurityCommandCenter />} />
            <Route path="jwt-lab" element={<JwtAttackLab />} />
            <Route path="file-upload-lab" element={<FileUploadSecurityLab />} />
            <Route path="identity-security" element={<IdentitySecurityCenter />} />
            <Route path="kerberos-security" element={<KerberosSecurityCommandCenter />} />
            <Route path="smb-netbios" element={<SmbNetbiosCommandCenter />} />
            <Route path="password-spray" element={<PasswordSprayCommandCenter />} />
            <Route path="saml-security" element={<SamlSecurityCommandCenter />} />
            <Route path="oast" element={<OastDashboard />} />
            <Route path="verification/oob" element={<OobVerification />} />
            <Route path="template-engine" element={<TemplateEngineWorkbench />} />
            <Route path="ast-fuzzing" element={<AstFuzzingStudio />} />
            <Route path="feedback-loop" element={<FeedbackLoopVerification />} />
            <Route path="council-queue" element={<CouncilHitlQueue />} />
            <Route path="roe-approvals" element={<RoeApprovals />} />
            <Route path="sso-config" element={<SsoDashboard />} />
            <Route path="digital-twin" element={<DigitalTwinSimulator />} />
            <Route path="digital-twin/:clientId" element={<DigitalTwinSimulator />} />
            <Route path="nexus-swarm" element={<NexusSovereignSwarm />} />
            <Route path="graphql-security" element={<GraphqlSecurityCommandCenter />} />
            <Route path="cicd-security" element={<CicdPipelineSecurityCommandCenter />} />
            <Route path="serverless-security" element={<ServerlessSecurityCommandCenter />} />
            <Route path="findings" element={<FindingsCommandCenter />} />
            <Route path="threat-intel" element={<ThreatIntelHub />} />
            <Route path="intel-map" element={<App />} />
            <Route path="incident-response" element={<IncidentResponseCenter />} />
            <Route path="vuln-intel" element={<VulnIntelDashboard />} />
            <Route path="dark-web" element={<DarkWebMonitor />} />
            <Route path="threat-hunting" element={<ThreatHuntingWorkbench />} />
            <Route path="threat-analysis" element={<ThreatAnalysisCenter />} />
            <Route path="engine-catalog" element={<EngineClientCatalog />} />
            <Route path="engine-reliability" element={<EngineReliability />} />
            <Route path="admin" element={<AdminManagement />} />
            {/* ── Client Management routes ────────────────────────────────────── */}
            <Route path="clients" element={<Clients />} />
            <Route path="clients/new" element={<ClientNew />} />
            <Route path="clients/:id" element={<ClientDetail />} />
            <Route path="clients/:id/engagements" element={<ClientEngagements />} />
            <Route path="clients/:id/evidence" element={<ClientEvidenceVault />} />
            <Route path="clients/:id/discovery/saas-idp" element={<ClientSaasIdpDiscovery />} />
            <Route path="jobs" element={<JobsDashboard />} />
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
            <Route path="kill-chain" element={<KillChainOrchestrator />} />
            <Route path="ai-analysis" element={<AIAnalysisEngine />} />
            <Route path="exploit-lab" element={<ExploitResearchLab />} />
            <Route path="agents" element={<AgentManagement />} />
            <Route path="audit-log" element={<AuditLog />} />
            <Route path="billing" element={<Billing />} />
            <Route path="playbooks" element={<PlaybookBuilder />} />
            <Route path="ask" element={<AskWeissman />} />
            <Route
              path="ceo"
              element={
                <CeoProtectedRoute>
                  <CeoCommandCenter />
                </CeoProtectedRoute>
              }
            />
            <Route path="*" element={<NotFound />} />
            {/* ─────────────────────────────────────────────────────────────────── */}
          </Route>
          {/* Fallback for any path outside the protected outlet */}
          <Route path="*" element={<NotFound />} />
        </Routes>
        </RateLimitProvider>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
    </RootErrorBoundary>
  </React.StrictMode>,
)
