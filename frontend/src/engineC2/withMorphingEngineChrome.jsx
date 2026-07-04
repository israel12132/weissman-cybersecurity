import MorphingEngineChrome from './MorphingEngineChrome'

/**
 * Higher-order component — physically envelopes engine weapons in morphing C2 chrome.
 * @template {Record<string, unknown>} P
 * @param {React.ComponentType<P>} PageComponent
 * @param {Partial<import('./types').EngineUiManifest>} [manifestHint]
 */
export function withMorphingEngineChrome(PageComponent, manifestHint = null) {
  function WrappedPage(props) {
    return (
      <MorphingEngineChrome manifest={manifestHint} {...props}>
        <PageComponent {...props} />
      </MorphingEngineChrome>
    )
  }
  WrappedPage.displayName = `WithMorphingC2(${PageComponent.displayName || PageComponent.name || 'Page'})`
  return WrappedPage
}

export { MorphingEngineChrome }
