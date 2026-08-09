/**
 * Deferred engines registry loader — keeps 200KB+ catalog out of tactical boot shell.
 */

/** @type {Promise<typeof import('./enginesRegistry.js')> | null} */
let registryPromise = null

/** @type {typeof import('./enginesRegistry.js') | null} */
let registryModule = null

export function loadEnginesRegistry() {
  if (registryModule) return Promise.resolve(registryModule)
  if (!registryPromise) {
    registryPromise = import(
      /* webpackChunkName: "data-engines-registry" */
      './enginesRegistry.js'
    ).then((mod) => {
      registryModule = mod
      return mod
    }).catch((err) => {
      // Clear the memoized promise so a later call can retry instead of
      // permanently resolving to the same rejection.
      registryPromise = null
      throw err
    })
  }
  return registryPromise
}

export function prefetchEnginesRegistry() {
  void loadEnginesRegistry().catch(() => undefined)
}

export function getEnginesRegistrySync() {
  return registryModule
}
