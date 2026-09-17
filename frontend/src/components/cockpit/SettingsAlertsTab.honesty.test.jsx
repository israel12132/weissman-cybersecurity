import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SettingsAlertsTab.jsx'),
  'utf8',
)

describe('SettingsAlertsTab live-only truth', () => {
  it('does not paint safe-mode OFF when the settings store is down', () => {
    expect(src).not.toMatch(/settingsUnavailable \? false/)
    expect(src).toMatch(/data-testid="settings-alerts-unavailable"/)
    expect(src).toMatch(/!settingsUnavailable &&/)
  })
})
