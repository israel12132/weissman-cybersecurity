import React from 'react'
import { Link } from 'react-router-dom'

/**
 * Catches render errors in child routes so a single bad view does not blank the entire app shell.
 */
export default class RouteErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    if (import.meta.env.DEV) {
      console.error('[CommandCenter]', error, info?.componentStack)
    }
  }

  render() {
    if (this.state.error) {
      const msg = this.state.error?.message || 'Unexpected error'
      return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-[#09090b] text-white p-8">
          <h1 className="text-lg font-semibold text-red-400 mb-2">This view crashed</h1>
          <p className="text-sm text-white/60 mb-6 max-w-lg text-center font-mono break-words">{msg}</p>
          <div className="flex gap-4">
            <button
              type="button"
              onClick={() => this.setState({ error: null })}
              className="px-4 py-2 rounded-lg border border-white/20 text-sm hover:bg-white/10"
            >
              Try again
            </button>
            <Link
              to="/"
              className="px-4 py-2 rounded-lg border border-cyan-500/40 text-cyan-400 text-sm hover:bg-cyan-500/10"
            >
              War Room
            </Link>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
