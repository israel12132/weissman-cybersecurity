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
    })
  }
  return registryPromise
}

export function prefetchEnginesRegistry() {
  void loadEnginesRegistry()
}

export function getEnginesRegistrySync() {
  return registryModule
}
