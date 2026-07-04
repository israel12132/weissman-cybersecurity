/**
 * Widget / data micro-chunk prefetch — isolated from route prefetch to avoid import cycles.
 */
export function prefetchCapability(cap) {
  if (cap === 'ast') {
    void import(/* webpackChunkName: "widget-ast-tree" */ '../engineC2/modules/AstTreeViewer.jsx')
  }
  if (cap === 'battlespace') {
    void import(/* webpackChunkName: "widget-battlespace" */ '../battlespace/BattlespaceTopology.jsx')
  }
  if (cap === 'registry') {
    void import(/* webpackChunkName: "data-engines-registry" */ '../lib/enginesRegistry.js')
  }
}
