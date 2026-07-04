/**
 * Lazy WASM loader for AST mutation capping (weissman-ast-cap).
 */

/** @type {Promise<{ cap_ast_mutations: (lines: string[], maxNodes: number, maxBytes: number) => string[] }> | null} */
let wasmPromise = null

export function loadAstCapWasm() {
  if (!wasmPromise) {
    wasmPromise = import('../wasm/weissman_ast_cap.js')
      .then(async (mod) => {
        await mod.default()
        return mod
      })
      .catch(() => null)
  }
  return wasmPromise
}

export function prefetchAstCapWasm() {
  void loadAstCapWasm()
}

/**
 * Cap mutation lines — WASM when available, JS fallback otherwise.
 */
export async function capAstMutations(lines, maxNodes, maxBytes) {
  const list = Array.isArray(lines) ? lines.map(String) : []
  const wasm = await loadAstCapWasm()
  if (wasm?.cap_ast_mutations) {
    const arr = wasm.cap_ast_mutations(list, maxNodes, maxBytes)
    return Array.from(arr)
  }
  let bytes = 0
  const out = []
  for (const line of list.slice(0, maxNodes)) {
    if (bytes + line.length > maxBytes) break
    bytes += line.length
    out.push(line)
  }
  return out
}
