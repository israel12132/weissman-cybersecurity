/**
 * Serialize / restore the findings filter state to URL query params so a filtered
 * view is shareable and bookmarkable. Pure functions — no React, fully testable.
 *
 * Params: q (search), sev (severity), status, engine, kev (1). Empty/default
 * values are omitted so a clean view yields a clean URL.
 */

const KEYS = {
  globalFilter: 'q',
  severityFilter: 'sev',
  statusFilter: 'status',
  engineFilter: 'engine',
}

/** @returns {Record<string,string>} only the non-empty params */
export function encodeFindingsFilters(state = {}) {
  const out = {}
  for (const [stateKey, param] of Object.entries(KEYS)) {
    const v = state[stateKey]
    if (v != null && String(v).trim() !== '') out[param] = String(v)
  }
  if (state.kevFilter) out.kev = '1'
  return out
}

/**
 * @param {URLSearchParams | Record<string,string>} params
 * @returns {{globalFilter:string,severityFilter:string,statusFilter:string,engineFilter:string,kevFilter:boolean}}
 */
export function decodeFindingsFilters(params) {
  const get = (k) => (
    typeof params?.get === 'function' ? (params.get(k) ?? '') : (params?.[k] ?? '')
  )
  return {
    globalFilter: get('q'),
    severityFilter: get('sev'),
    statusFilter: get('status'),
    engineFilter: get('engine'),
    kevFilter: get('kev') === '1',
  }
}

/** True when a decoded filter set carries at least one active filter. */
export function hasAnyFilter(state = {}) {
  return Boolean(
    state.globalFilter || state.severityFilter || state.statusFilter
    || state.engineFilter || state.kevFilter,
  )
}
