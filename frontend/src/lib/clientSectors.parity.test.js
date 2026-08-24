import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { CLIENT_SECTORS } from './clientSectors'

const RUST_SOURCE = resolve(
  import.meta.dirname,
  '../../../backend/weissman-core/src/models/client_sector.rs',
)

function rustSectors() {
  const src = readFileSync(RUST_SOURCE, 'utf8')
  const block = src.match(/pub const CLIENT_SECTORS: &\[&str\] = &\[(.*?)\];/s)
  if (!block) throw new Error(`CLIENT_SECTORS not found in ${RUST_SOURCE}`)
  return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
}

describe('client sector catalog parity', () => {
  it('frontend list matches weissman-core CLIENT_SECTORS exactly, including order', () => {
    expect(CLIENT_SECTORS).toEqual(rustSectors())
  })

  it('every sector has an i18n label in both locales', async () => {
    const [en, he] = await Promise.all([
      import('../i18n/locales/en.json'),
      import('../i18n/locales/he.json'),
    ])
    for (const sector of CLIENT_SECTORS) {
      expect(en.default.pages.clientNew[`sector_${sector}`]).toBeTruthy()
      expect(he.default.pages.clientNew[`sector_${sector}`]).toBeTruthy()
    }
  })
})
