import React from 'react'
import i18n from '../../i18n'
import Button from '../ui/Button'

const NS = 'components.cockpitWidgets.cockpitTabErrorBoundary'

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
      const msg = this.state.error?.message || i18n.t(`${NS}.unexpected`)
      return (
        <div className="p-8 max-w-2xl mx-auto">
          <h2 className="text-sm font-semibold text-red-400 mb-2">{i18n.t(`${NS}.title`)}</h2>
          <p className="text-xs text-white/50 mb-3">
            {this.props.tabLabel
              ? i18n.t(`${NS}.tabFailed`, { label: this.props.tabLabel })
              : i18n.t(`${NS}.viewFailed`)}{' '}
            {i18n.t(`${NS}.switchHint`)}
          </p>
          <p className="text-[11px] font-mono text-white/40 break-words mb-4">{msg}</p>
          <Button variant="unstyled"
            type="button"
            onClick={() => this.setState({ error: null })}
            className="px-4 py-2 rounded-lg border border-white/20 text-sm text-white/80 hover:bg-white/10"
          >
            {i18n.t(`${NS}.retry`)}
          </Button>
        </div>
      )
    }
    return this.props.children
  }
}
