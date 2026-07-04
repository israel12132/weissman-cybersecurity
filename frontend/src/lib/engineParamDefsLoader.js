/**
 * Deferred generated param profiles — 450KB+ isolated from boot shell.
 */

/** @type {Promise<Record<string, unknown[]>> | null} */
let generatedPromise = null

/** @type {Record<string, unknown[]> | null} */
let generatedCache = null

export function loadGeneratedParamDefs() {
  if (generatedCache) return Promise.resolve(generatedCache)
  if (!generatedPromise) {
    generatedPromise = import(
      /* webpackChunkName: "data-engine-params" */
      './engineParamDefs.generated.js'
    ).then((mod) => {
      generatedCache = mod.GENERATED_PARAM_DEFS || {}
      return generatedCache
    })
  }
  return generatedPromise
}

export function prefetchEngineParamDefs() {
  void loadGeneratedParamDefs()
}

export function getGeneratedParamDefsSync() {
  return generatedCache
}
