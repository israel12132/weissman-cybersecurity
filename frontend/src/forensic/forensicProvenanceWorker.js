/**
 * Web Worker — WASM cryptographic provenance verification off the main thread.
 * Never fails silently: posts explicit verified | tamper | error states.
 */

let wasmReady = false
let wasmApi = null

async function initWasm() {
  if (wasmReady && wasmApi) return wasmApi
  try {
    const mod = await import('../wasm/weissman_ui_provenance.js')
    await mod.default()
    wasmApi = mod
    wasmReady = true
    return wasmApi
  } catch (err) {
    throw new Error(`WASM provenance load failed: ${err?.message || err}`)
  }
}

/**
 * @param {MessageEvent} event
 */
self.onmessage = async (event) => {
  const { id, type, payload } = event.data || {}
  try {
    const wasm = await initWasm()
    let result

    switch (type) {
      case 'verify_capabilities': {
        const { bodyJson, manifestJson, secret } = payload
        const integrityRaw = wasm.verify_capabilities_integrity(bodyJson, manifestJson)
        const integrity = JSON.parse(integrityRaw)
        if (!integrity.ok) {
          result = {
            status: 'tamper',
            layer: 'integrity',
            detail: integrity.status || 'hash_mismatch',
            integrity,
          }
          break
        }
        if (secret) {
          const hmacRaw = wasm.verify_capabilities_json(bodyJson, manifestJson, secret)
          const hmac = JSON.parse(hmacRaw)
          result = {
            status: hmac.ok ? 'verified' : 'tamper',
            layer: 'hmac',
            detail: hmac.status,
            integrity,
            hmac,
          }
        } else {
          result = {
            status: 'verified',
            layer: 'integrity_only',
            detail: 'SHA-256 payload hash verified (HMAC key not provisioned)',
            integrity,
          }
        }
        break
      }
      case 'verify_telemetry': {
        const {
          eventJson,
          manifestHash,
          secret,
          beliefProbsJson,
          fusionMode,
          reportedCollapse,
        } = payload
        const raw = wasm.verify_telemetry_json(
          eventJson,
          manifestHash,
          secret || '',
          beliefProbsJson || '[]',
          fusionMode || 'hybrid',
          reportedCollapse ?? Number.NaN,
        )
        const parsed = JSON.parse(raw)
        result = {
          status: parsed.ok ? 'verified' : 'tamper',
          layer: 'telemetry',
          detail: parsed.detail,
          eventHash: parsed.event_hash,
          collapseBelief: parsed.collapse_belief,
        }
        break
      }
      case 'collapse_belief': {
        const belief = wasm.collapse_belief_json(
          payload.probsJson || '[]',
          payload.fusionMode || 'hybrid',
        )
        result = { status: 'verified', collapseBelief: belief }
        break
      }
      default:
        throw new Error(`unknown worker message type: ${type}`)
    }

    self.postMessage({ id, ok: true, result })
  } catch (err) {
    self.postMessage({
      id,
      ok: false,
      error: err?.message || String(err),
      status: 'error',
    })
  }
}
