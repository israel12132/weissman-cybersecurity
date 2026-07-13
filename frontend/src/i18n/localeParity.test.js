import { describe, it, expect } from 'vitest'
import en from './locales/en.json'
import he from './locales/he.json'

/**
 * Guard: the English and Hebrew locale trees must expose the exact same key
 * set. A key present in one but not the other means a user in that language
 * sees a raw i18n key instead of a translation — unacceptable for a bilingual
 * product. This test fails loudly the moment the two drift.
 */
function flatten(obj, prefix = '', acc = {}) {
  for (const k of Object.keys(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    const v = obj[k]
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, acc)
    else acc[key] = true
  }
  return acc
}

describe('i18n locale parity (en ↔ he)', () => {
  const enKeys = flatten(en)
  const heKeys = flatten(he)

  it('has no keys present in English but missing from Hebrew', () => {
    const missing = Object.keys(enKeys).filter((k) => !(k in heKeys))
    expect(missing, `Missing in he.json:\n${missing.join('\n')}`).toEqual([])
  })

  it('has no keys present in Hebrew but missing from English', () => {
    const missing = Object.keys(heKeys).filter((k) => !(k in enKeys))
    expect(missing, `Missing in en.json:\n${missing.join('\n')}`).toEqual([])
  })
})
