/**
 * Tactical boot entry — minimal shell; heavy app loads after locale + SW bootstrap.
 */
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { bootstrapTacticalShell } from './boot/tacticalBoot'
import RouteLoader from './components/ui/RouteLoader'
import './i18n'
import './index.css'

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
          <h1 className="text-lg font-semibold text-red-400 mb-2">Failed to load Command Center</h1>
          <p className="text-sm text-slate-400 mb-6 max-w-lg text-center break-words">{msg}</p>
          <button
            type="button"
            className="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10"
            onClick={() => window.location.reload()}
          >
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

function mount() {
  const root = document.getElementById('root')
  import('./TacticalApp').then(({ default: TacticalApp, TacticalProviders }) => {
    ReactDOM.createRoot(root).render(
      <React.StrictMode>
        <RootErrorBoundary>
          <BrowserRouter basename="/command-center">
            <TacticalProviders>
              <React.Suspense fallback={<RouteLoader />}>
                <TacticalApp />
              </React.Suspense>
            </TacticalProviders>
          </BrowserRouter>
        </RootErrorBoundary>
      </React.StrictMode>,
    )
  })
}

const bootEl = document.getElementById('root')
if (bootEl) {
  bootEl.innerHTML = '<div class="min-h-[100dvh] flex items-center justify-center bg-[#030508]"><div class="h-8 w-8 rounded-full border-2 border-cyan-400/30 border-t-cyan-400 animate-spin" aria-hidden="true"></div></div>'
}

bootstrapTacticalShell()
  .then(mount)
  .catch((err) => {
    console.error('[tactical-boot]', err)
    mount()
  })
