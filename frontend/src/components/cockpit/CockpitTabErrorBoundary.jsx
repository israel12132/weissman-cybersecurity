import React from 'react'

/**
 * Isolates cockpit tab render failures so one bad view does not blank the whole command center.
 */
export default class CockpitTabErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    if (import.meta.env.DEV) {
      const label = this.props.tabLabel || this.props.tabId || 'tab'
      console.error('[CockpitTab]', label, error, info?.componentStack)
    }
  }

  render() {
    if (this.state.error) {
      const msg = this.state.error?.message || 'Unexpected error'
      return (
        <div className="p-8 max-w-2xl mx-auto">
          <h2 className="text-sm font-semibold text-red-400 mb-2">Tab error</h2>
          <p className="text-xs text-white/50 mb-3">
            {this.props.tabLabel ? `“${this.props.tabLabel}” could not render.` : 'This view could not render.'}{' '}
            Switch to another tab or retry.
          </p>
          <p className="text-[11px] font-mono text-white/40 break-words mb-4">{msg}</p>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="px-4 py-2 rounded-lg border border-white/20 text-sm text-white/80 hover:bg-white/10"
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
