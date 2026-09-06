import { describe, it, expect, beforeEach } from 'vitest'
import {
  ACTION_KINDS,
  BUILTIN_PLAYBOOKS,
  ENGINE_FILTER_OPTIONS,
  PLAYBOOK_CATEGORIES,
  CUSTOM_STORAGE_KEY,
  blankPlaybook,
  templateToDraft,
  isValidPlaybookDraft,
  parseImportedPlaybook,
  loadCustomTemplates,
  saveCustomTemplate,
  deleteCustomTemplate,
  mergeCatalog,
  filterCatalog,
  actionKindLabel,
} from './playbookCatalog.js'

function memoryStorage(seed = {}) {
  const map = { ...seed }
  return {
    getItem: (k) => (k in map ? map[k] : null),
    setItem: (k, v) => { map[k] = String(v) },
    removeItem: (k) => { delete map[k] },
    _map: map,
  }
}

describe('playbookCatalog', () => {
  it('ships a dozen+ operator-grade builtins with real DSL shapes', () => {
    expect(BUILTIN_PLAYBOOKS.length).toBeGreaterThanOrEqual(12)
    expect(ACTION_KINDS.map((a) => a.kind)).toEqual([
      'set_status', 'slack_notify', 'webhook', 'open_pr', 'isolate_host', 'page_oncall', 'http_post',
    ])
    const ids = new Set()
    for (const pb of BUILTIN_PLAYBOOKS) {
      expect(ids.has(pb.id)).toBe(false)
      ids.add(pb.id)
      expect(PLAYBOOK_CATEGORIES).toContain(pb.category)
      expect(pb.enabled).toBeUndefined()
      expect(Array.isArray(pb.actions)).toBe(true)
      expect(pb.actions.length).toBeGreaterThan(0)
      expect(pb.trigger && typeof pb.trigger === 'object').toBe(true)
      expect(pb.trigger.cooldown_seconds).toBeGreaterThan(0)
      for (const a of pb.actions) {
        expect(ACTION_KINDS.some((k) => k.kind === a.kind)).toBe(true)
      }
      const engines = pb.trigger.engines || []
      for (const eng of engines) {
        expect(ENGINE_FILTER_OPTIONS).toContain(eng)
      }
    }
  })

  it('never enables a template draft (destructive actions stay off until save)', () => {
    for (const pb of BUILTIN_PLAYBOOKS) {
      const draft = templateToDraft(pb, (k, fb) => fb)
      expect(draft.enabled).toBe(false)
      expect(draft.name).toBe(pb.fallbackName)
      expect(draft.actions).toHaveLength(pb.actions.length)
      draft.actions[0].kind = 'mutated'
      expect(pb.actions[0].kind).not.toBe('mutated')
    }
  })

  it('blank playbook is a valid empty draft', () => {
    const blank = blankPlaybook()
    expect(isValidPlaybookDraft(blank)).toBe(true)
    expect(blank.actions).toEqual([])
    expect(blank.enabled).toBe(false)
  })

  it('rejects malformed drafts and imports', () => {
    expect(isValidPlaybookDraft(null)).toBe(false)
    expect(isValidPlaybookDraft([])).toBe(false)
    expect(isValidPlaybookDraft({ trigger: [], actions: [] })).toBe(false)
    expect(isValidPlaybookDraft({ actions: [{ kind: '' }] })).toBe(false)
    expect(parseImportedPlaybook('not-json')).toBeNull()
    expect(parseImportedPlaybook({ actions: [{ no_kind: true }] })).toBeNull()
  })

  it('parses exported playbook JSON into a disabled draft', () => {
    const draft = parseImportedPlaybook({
      name: 'Imported',
      description: 'from file',
      enabled: true,
      trigger: { severity: ['high'], kev: true },
      actions: [{ kind: 'set_status', params: { status: 'OPEN' } }],
    })
    expect(draft.enabled).toBe(false)
    expect(draft.name).toBe('Imported')
    expect(draft.trigger.kev).toBe(true)
    expect(draft.actions[0].params.status).toBe('OPEN')
  })

  it('round-trips custom templates through storage', () => {
    const storage = memoryStorage()
    expect(loadCustomTemplates(storage)).toEqual([])
    const saved = saveCustomTemplate(
      {
        name: 'Night desk',
        description: 'pages identity',
        trigger: { severity: ['critical'], engines: ['leak_hunter'] },
        actions: [{ kind: 'page_oncall', params: { team: 'identity-oncall' } }],
      },
      {},
      storage,
    )
    expect(saved.id).toMatch(/^custom-/)
    const loaded = loadCustomTemplates(storage)
    expect(loaded).toHaveLength(1)
    expect(loaded[0].name).toBe('Night desk')
    expect(loaded[0].category).toBe('custom')
    const remaining = deleteCustomTemplate(saved.id, storage)
    expect(remaining).toHaveLength(0)
    expect(JSON.parse(storage._map[CUSTOM_STORAGE_KEY])).toEqual([])
  })

  it('skips corrupt storage payloads', () => {
    expect(loadCustomTemplates(memoryStorage({ [CUSTOM_STORAGE_KEY]: '{not json' }))).toEqual([])
    expect(loadCustomTemplates(memoryStorage({ [CUSTOM_STORAGE_KEY]: '{"x":1}' }))).toEqual([])
    expect(loadCustomTemplates(null)).toEqual([])
  })

  it('refuses to save a nameless or invalid custom template', () => {
    const storage = memoryStorage()
    expect(saveCustomTemplate({ name: '  ', actions: [] }, {}, storage)).toBeNull()
    expect(saveCustomTemplate(null, { name: 'x' }, storage)).toBeNull()
  })

  it('merges builtins ahead of custom and filters by query/category', () => {
    const custom = [{ id: 'custom-1', category: 'custom', name: 'Night desk', trigger: {}, actions: [] }]
    const merged = mergeCatalog(custom)
    expect(merged[0].id).toBe(BUILTIN_PLAYBOOKS[0].id)
    expect(merged.at(-1).id).toBe('custom-1')
    expect(filterCatalog(merged, 'night desk').map((p) => p.id)).toEqual(['custom-1'])
    expect(filterCatalog(merged, '', 'containment').every((p) => p.category === 'containment')).toBe(true)
    expect(filterCatalog(merged, 'leak_hunter').some((p) => p.id === 'secret-leak-break-glass')).toBe(true)
  })

  it('labels known action kinds via i18n fallback', () => {
    expect(actionKindLabel('isolate_host', (k, fb) => fb)).toBe('isolate_host')
    expect(actionKindLabel('not-a-kind', (k) => k)).toBe('not-a-kind')
  })
})

describe('playbookCatalog storage isolation', () => {
  beforeEach(() => {
    try { localStorage.removeItem(CUSTOM_STORAGE_KEY) } catch { /* jsdom */ }
  })

  it('uses real localStorage when no storage is passed', () => {
    const saved = saveCustomTemplate({
      name: 'From default storage',
      trigger: {},
      actions: [{ kind: 'webhook', params: {} }],
    })
    expect(saved).not.toBeNull()
    expect(loadCustomTemplates().some((t) => t.name === 'From default storage')).toBe(true)
    deleteCustomTemplate(saved.id)
    expect(loadCustomTemplates()).toHaveLength(0)
  })
})
