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
            <Route path="ceo" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
    </RootErrorBoundary>
  </React.StrictMode>,
)
