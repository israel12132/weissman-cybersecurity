/**
 * Tactical boot entry — minimal shell; heavy app loads after locale + SW bootstrap.
 */
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import { bootstrapTacticalShell } from './boot/tacticalBoot'
import RouteLoader from './components/ui/RouteLoader'
import './i18n'
import './index.css'
import Button from './components/ui/Button'

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
        <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-[var(--text-secondary)] p-8 font-mono">
          <h1 className="text-lg font-semibold text-red-400 mb-2">Failed to load Command Center</h1>
          <p className="text-sm text-[var(--text-tertiary)] mb-6 max-w-lg text-center break-words">{msg}</p>
          <Button variant="unstyled"
            type="button"
            className="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10"
            onClick={() => window.location.reload()}
          >
            Reload
          </Button>
        </div>
      )
    }
    return this.props.children
  }
}

function renderBootFailure(root, err) {
  if (import.meta.env.DEV) console.error('[tactical-boot] failed to load Command Center', err)
  if (!root) return
  // CSP is `script-src 'self'` in production, so no inline onclick — wire the
  // reload button up with addEventListener instead.
  root.innerHTML =
    '<div class="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-[var(--text-secondary)] p-8 font-mono">' +
    '<h1 class="text-lg font-semibold text-red-400 mb-2">Failed to load Command Center</h1>' +
    '<p class="text-sm text-[var(--text-tertiary)] mb-6 max-w-lg text-center">A required module could not be loaded. This can happen after a new deploy — reloading usually resolves it.</p>' +
    '<button id="tactical-boot-reload" type="button" class="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10">Reload</button>' +
    '</div>'
  document
    .getElementById('tactical-boot-reload')
    ?.addEventListener('click', () => window.location.reload())
}

function mount() {
  const root = document.getElementById('root')
  const load = () =>
    import('./TacticalApp').then(({ default: TacticalApp, TacticalProviders }) => {
      ReactDOM.createRoot(root).render(
        <React.StrictMode>
          <RootErrorBoundary>
            <BrowserRouter
              basename="/command-center"
              // Opt in to v7 behaviour while still on v6, so the version bump itself carries no
              // behaviour change. `v7_startTransition` wraps route state updates in
              // React.startTransition: during a lazy-chunk load the PREVIOUS page stays on screen
              // instead of the <React.Suspense fallback={<RouteLoader />}> below flashing in.
              // `v7_relativeSplatPath` fixes relative-link resolution inside splat routes.
              future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            >
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
  // The root chunk is the one load that MUST succeed for anything to render, and
  // the mounted RootErrorBoundary can't catch a failure of its own import. Retry
  // a couple of times (transient blip / stale-deploy chunk rotation), then fall
  // back to an explicit reload prompt instead of an eternal boot spinner.
  return load()
    .catch(() => new Promise((r) => setTimeout(r, 250)).then(load))
    .catch(() => new Promise((r) => setTimeout(r, 500)).then(load))
    .catch((err) => renderBootFailure(root, err))
}

// Last-resort visibility for promise rejections that escape every local handler
// (e.g. a chunk load that rejects outside the retry path) — otherwise they are
// silent, since there is no other unhandledrejection listener in the app.
window.addEventListener('unhandledrejection', (event) => {
  if (import.meta.env.DEV) console.error('[tactical-boot] unhandled rejection', event.reason)
})

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
