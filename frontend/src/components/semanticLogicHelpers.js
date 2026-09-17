/** Live Semantic Logic payloads — graph + reasoning, never empty-success theater. */

export function reasoningFromPayload(log) {
  if (!log || typeof log !== 'object') return ''
  const text = log.reasoning_text ?? log.log
  return typeof text === 'string' ? text : ''
}

export function emptyGraphCopy(sm, t, ns) {
  if (sm?.message) return sm.message
  if (Array.isArray(sm?.logs) && sm.logs.length) {
    return t(`${ns}.graph_not_persisted`)
  }
  return t(`${ns}.no_openapi`)
}
