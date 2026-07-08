import React, { useEffect } from 'react'
import { Routes, Route, Outlet, useLocation } from 'react-router-dom'
import { MotionConfig } from 'framer-motion'
import { ProtectedProviders } from './providers/ProtectedProviders'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import ProtectedRoute from './components/cockpit/ProtectedRoute'
import CeoProtectedRoute from './components/ceo/CeoProtectedRoute'
import RequireRole from './components/auth/RequireRole'
import RouteErrorBoundary from './components/RouteErrorBoundary'
import { ToastProvider } from './components/ui/Toaster'
import RateLimitProvider from './components/RateLimitProvider'
import KeyboardShortcuts from './components/ui/KeyboardShortcuts'
import SkipToContent from './components/ui/SkipToContent'
import NotFound from './components/ui/NotFound'
import RouteLoader from './components/ui/RouteLoader'
import { predictChainFromRoute } from './boot/intentPrefetch'
import {
  Cockpit,
  Login,
  App,
  SystemCore,
  ReportView,
  AttackSurfaceGraph,
  SemanticLogicEngine,
  QuantumTimingProfiler,
  AIRedteamArena,
  ZeroDayRadar,
  CICDThreatMatrix,
  MemoryForensicsLab,
  AttackChainView,
  EngineMatrix,
  EngineDetail,
  OsintEngineProfile,
  TopTierEngineHub,
  TopTierEngineProfile,
  StrategicEngineProgram,
  BusinessEngineProfile,
  ThreatEmulation,
  SupplyChainHub,
  NetworkIntelligence,
  CloudControlTower,
  CloudPostureCommandCenter,
  IacSecurityCenter,
  AttackSurfaceManagement,
  DnsDomainPosture,
  WebCachePosture,
  TransportSecurityCommandCenter,
  HttpSmugglingPosture,
  PkiTlsCommandCenter,
  EmailDnsPosture,
  PqcRadar,
  EdDetectionSurface,
  WafBypassLab,
  WebSocketSecurityCommandCenter,
  JwtAttackLab,
  FileUploadSecurityLab,
  OastDashboard,
  OobVerification,
  TemplateEngineWorkbench,
  AstFuzzingStudio,
  FeedbackLoopVerification,
  CouncilHitlQueue,
  RoeApprovals,
  SsoDashboard,
  NexusSovereignSwarm,
  RiskSuperpositionCollapse,
  SovereignDefenseMatrix,
  GraphqlSecurityCommandCenter,
  CicdPipelineSecurityCommandCenter,
  ServerlessSecurityCommandCenter,
  DigitalTwinSimulator,
  FindingsCommandCenter,
  AdminManagement,
  DomainDiscovery,
  ThreatIntelHub,
  IncidentResponseCenter,
  VulnIntelDashboard,
  FinancialRisk,
  AttackPaths,
  AttackCoverage,
  SecurityPosture,
  IocFeed,
  UebaAnomalies,
  FindingSuppressions,
  ExecutiveOverview,
  AgentManagement,
  DarkWebMonitor,
  ThreatHuntingWorkbench,
  ThreatAnalysisCenter,
  EngineClientCatalog,
  RateLimitAnalytics,
  MobileSecurity,
  OtIcsSecurity,
  NetworkProtocols,
  SocialEngineering,
  RemediationHub,
  EngineManagementConsole,
  EngineReliability,
  SystemConfiguration,
  MetricsDashboard,
  CeoVault,
  CeoCommandCenter,
  SupremeNerveCenter,
  RiskGraphVisualization,
  ComplianceFrameworks,
  SBOMBrowser,
  IntegrationManager,
  AlertRulesEngine,
  ScanScheduler,
  ContainmentRulesBuilder,
  BaselineAndDrift,
  IdentityContextManager,
  IdentitySecurityCenter,
  KerberosSecurityCommandCenter,
  SmbNetbiosCommandCenter,
  PasswordSprayCommandCenter,
  SamlSecurityCommandCenter,
  KillChainOrchestrator,
  AIAnalysisEngine,
  ExploitResearchLab,
  Clients,
  ClientNew,
  ClientDetail,
  ClientIntegrations,
  ClientEngagements,
  ClientEvidenceVault,
  ClientSaasIdpDiscovery,
  JobsDashboard,
  StatusPage,
  AuditLog,
  PlaybookBuilder,
  AskWeissman,
  Billing,
} from './routing/routeChunks'

function ChainPredictor() {
  const { pathname } = useLocation()
  useEffect(() => {
    predictChainFromRoute(pathname)
  }, [pathname])
  return null
}

function ProtectedOutlet() {
  const location = useLocation()
  return (
    <ProtectedProviders>
      <ChainPredictor />
      <RouteErrorBoundary key={location.pathname}>
        <React.Suspense fallback={<RouteLoader />}>
          <Outlet />
        </React.Suspense>
      </RouteErrorBoundary>
    </ProtectedProviders>
  )
}

export default function TacticalApp() {
  return (
    <>
      <SkipToContent />
      <KeyboardShortcuts />
      <Routes>
        <Route
          path="login"
          element={
            <React.Suspense fallback={<RouteLoader />}>
              <Login />
            </React.Suspense>
          }
        />
        <Route
          path="status"
          element={
            <React.Suspense fallback={<RouteLoader />}>
              <StatusPage />
            </React.Suspense>
          }
        />
        <Route path="/" element={<ProtectedRoute><ProtectedOutlet /></ProtectedRoute>}>
          <Route index element={<CeoProtectedRoute><Cockpit ceoIntegrated /></CeoProtectedRoute>} />
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
          <Route path="superposition-collapse" element={<RiskSuperpositionCollapse />} />
          <Route path="sovereign-defense-matrix" element={<SovereignDefenseMatrix />} />
          <Route path="graphql-security" element={<GraphqlSecurityCommandCenter />} />
          <Route path="cicd-security" element={<CicdPipelineSecurityCommandCenter />} />
          <Route path="serverless-security" element={<ServerlessSecurityCommandCenter />} />
          <Route path="findings" element={<FindingsCommandCenter />} />
          <Route path="threat-intel" element={<ThreatIntelHub />} />
          <Route path="intel-map" element={<App />} />
          <Route path="incident-response" element={<IncidentResponseCenter />} />
          <Route path="vuln-intel" element={<VulnIntelDashboard />} />
          <Route path="financial-risk" element={<FinancialRisk />} />
          <Route path="attack-paths" element={<AttackPaths />} />
          <Route path="attack-coverage" element={<AttackCoverage />} />
          <Route path="security-posture" element={<SecurityPosture />} />
          <Route path="iocs" element={<IocFeed />} />
          <Route path="ueba" element={<UebaAnomalies />} />
          <Route path="suppressions" element={<FindingSuppressions />} />
          <Route path="overview" element={<ExecutiveOverview />} />
          <Route path="dark-web" element={<DarkWebMonitor />} />
          <Route path="threat-hunting" element={<ThreatHuntingWorkbench />} />
          <Route path="threat-analysis" element={<ThreatAnalysisCenter />} />
          <Route path="engine-catalog" element={<EngineClientCatalog />} />
          <Route path="engine-reliability" element={<EngineReliability />} />
          <Route path="admin" element={<RequireRole min="ceo"><AdminManagement /></RequireRole>} />
          <Route path="clients" element={<Clients />} />
          <Route path="clients/new" element={<ClientNew />} />
          <Route path="clients/:id" element={<ClientDetail />} />
          <Route path="clients/:id/integrations" element={<ClientIntegrations />} />
          <Route path="clients/:id/engagements" element={<ClientEngagements />} />
          <Route path="clients/:id/evidence" element={<ClientEvidenceVault />} />
          <Route path="clients/:id/discovery/saas-idp" element={<ClientSaasIdpDiscovery />} />
          <Route path="jobs" element={<JobsDashboard />} />
          <Route path="rate-limits" element={<RateLimitAnalytics />} />
          <Route path="mobile-security" element={<MobileSecurity />} />
          <Route path="ot-ics" element={<OtIcsSecurity />} />
          <Route path="network-protocols" element={<NetworkProtocols />} />
          <Route path="social-engineering" element={<SocialEngineering />} />
          <Route path="remediation" element={<RemediationHub />} />
          <Route path="engine-management" element={<EngineManagementConsole />} />
          <Route path="system-config" element={<RequireRole min="admin"><SystemConfiguration /></RequireRole>} />
          <Route path="metrics" element={<MetricsDashboard />} />
          <Route path="ceo-vault" element={<RequireRole min="ceo"><CeoVault /></RequireRole>} />
          <Route path="risk-graph" element={<RiskGraphVisualization />} />
          <Route path="compliance" element={<ComplianceFrameworks />} />
          <Route path="sbom" element={<SBOMBrowser />} />
          <Route path="integrations" element={<IntegrationManager />} />
          <Route path="settings/integrations" element={<IntegrationManager />} />
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
          <Route path="ceo" element={<CeoProtectedRoute><CeoCommandCenter /></CeoProtectedRoute>} />
          <Route path="supreme-nerve-center" element={<RequireRole min="ceo"><SupremeNerveCenter /></RequireRole>} />
          <Route path="*" element={<NotFound />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  )
}

export function TacticalProviders({ children }) {
  return (
    <ThemeProvider>
      {/* Respect the OS "reduce motion" setting across all framer-motion animations. */}
      <MotionConfig reducedMotion="user">
        <AuthProvider>
          <ToastProvider>
            <RateLimitProvider>{children}</RateLimitProvider>
          </ToastProvider>
        </AuthProvider>
      </MotionConfig>
    </ThemeProvider>
  )
}
