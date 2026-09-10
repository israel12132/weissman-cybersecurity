import { useMemo, useState } from 'react'
import { useI18n } from '../i18n'
import { track } from '../lib/analytics'

type Severity = 'critical' | 'high' | 'medium' | 'info'
type View = 'exec' | 'tech'
type Loop = 'detect' | 'analyse' | 'validate' | 'respond'

type Finding = {
  id: 'F-1042' | 'F-0988' | 'F-0771' | 'F-0610'
  asset: string
  severity: Severity
  mitre: string[]
  epss: string
  kev: boolean
  loop: Loop
}

const SAMPLE: Finding[] = [
  { id: 'F-1042', asset: 'edge-web-01', severity: 'high', mitre: ['T1190', 'T1078'], epss: '0.84', kev: false, loop: 'validate' },
  { id: 'F-0988', asset: 'idp-core', severity: 'critical', mitre: ['T1133', 'T1078'], epss: '0.91', kev: true, loop: 'respond' },
  { id: 'F-0771', asset: 'laptop-soc-12', severity: 'medium', mitre: ['T1046'], epss: '—', kev: false, loop: 'detect' },
  { id: 'F-0610', asset: 'ot-plc-lab', severity: 'info', mitre: ['T1046'], epss: '—', kev: false, loop: 'analyse' },
]

const FILTERS: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'info']
const LOOP_KEYS: Record<Loop, string> = {
  detect: 'interactive.loopDetect',
  analyse: 'interactive.loopAnalyse',
  validate: 'interactive.loopValidate',
  respond: 'interactive.loopRespond',
}
const LOOPS = Object.keys(LOOP_KEYS) as Loop[]

export function InteractiveProduct() {
  const { t } = useI18n()
  const [view, setView] = useState<View>('tech')
  const [loop, setLoop] = useState<Loop>('detect')
  const [sev, setSev] = useState<(typeof FILTERS)[number]>('all')
  const [asset, setAsset] = useState('all')
  const [open, setOpen] = useState<string>(SAMPLE[1].id)
  const [pathOpen, setPathOpen] = useState(true)

  const assets = useMemo(() => ['all', ...new Set(SAMPLE.map((f) => f.asset))], [])
  const rows = SAMPLE.filter((f) => (sev === 'all' || f.severity === sev) && (asset === 'all' || f.asset === asset))
  const active = rows.find((f) => f.id === open) ?? rows[0]

  function interact(action: string, extra: Record<string, string> = {}) {
    track('product_demo_interact', { surface: 'experience', action, ...extra })
  }

  function selectFinding(id: string) {
    setOpen(id)
    interact('select_finding', { id })
  }

  function setLoopPhase(next: Loop) {
    setLoop(next)
    const match = SAMPLE.find((f) => f.loop === next)
    if (match) setOpen(match.id)
    interact('loop', { phase: next })
  }

  return (
    <div className="overflow-hidden rounded-[14px] border border-[var(--line)] bg-[#0a0e14] shadow-[var(--shadow)]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] px-4 py-3">
        <div>
          <p className="text-sm font-medium text-ink">{t('interactive.title')}</p>
          <p className="text-xs tracking-[0.14em] text-risk">{t('interactive.badge')}</p>
        </div>
        <span className="inline-flex items-center gap-2 text-xs text-ops">
          <span className="h-2 w-2 animate-pulse rounded-full bg-ops" />
          {t('interactive.stream')}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] px-4 py-3">
        <div role="tablist" aria-label={t('interactive.view')} className="flex gap-1">
          {(['exec', 'tech'] as const).map((v) => (
            <button
              key={v}
              type="button"
              role="tab"
              aria-selected={view === v}
              className={`min-h-11 rounded-[10px] px-3 text-sm transition duration-swift ${
                view === v ? 'bg-accent text-[#041016]' : 'text-muted hover:text-ink'
              }`}
              onClick={() => {
                setView(v)
                interact('view', { view: v })
              }}
            >
              {t(`interactive.view${v === 'exec' ? 'Exec' : 'Tech'}`)}
            </button>
          ))}
        </div>
        <p className="text-xs text-dim">{t('interactive.viewHint')}</p>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-[var(--line)] px-4 py-3" role="tablist" aria-label={t('interactive.loop')}>
        {LOOPS.map((id) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={loop === id}
            className={`min-h-11 rounded-[10px] px-3 text-sm transition duration-swift ${
              loop === id ? 'bg-elevated text-ink' : 'text-muted hover:text-ink'
            }`}
            onClick={() => setLoopPhase(id)}
          >
            {t(LOOP_KEYS[id])}
          </button>
        ))}
      </div>
      <p className="border-b border-[var(--line)] px-4 py-2 text-xs text-muted">{t(`interactive.loopHint.${loop}`)}</p>

      <div className="flex flex-wrap gap-2 border-b border-[var(--line)] px-4 py-3">
        <div role="group" aria-label={t('a11y.severityFilter')} className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              className={`min-h-11 rounded-[10px] px-3 text-sm transition duration-swift ${
                sev === f ? 'bg-accent/15 text-accent' : 'text-muted hover:text-ink'
              }`}
              aria-pressed={sev === f}
              onClick={() => {
                setSev(f)
                interact('filter_severity', { severity: f })
              }}
            >
              {t(`interactive.severity.${f}`)}
            </button>
          ))}
        </div>
        <label className="ms-auto flex min-h-11 items-center gap-2 text-sm text-muted">
          {t('interactive.asset')}
          <select
            className="min-h-11 rounded-[10px] border border-[var(--line)] bg-deep px-2 text-ink"
            value={asset}
            onChange={(e) => {
              setAsset(e.target.value)
              interact('filter_asset', { asset: e.target.value })
            }}
          >
            {assets.map((a) => (
              <option key={a} value={a}>
                {a === 'all' ? t('interactive.all') : a}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid lg:grid-cols-12">
        <div className="border-b border-[var(--line)] lg:col-span-7 lg:border-b-0 lg:border-e">
          <table className="w-full text-start text-sm">
            <thead className="text-[0.7rem] tracking-[0.12em] text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">{t('interactive.id')}</th>
                <th className="px-4 py-2 font-medium">{t('interactive.finding')}</th>
                <th className="px-4 py-2 font-medium">{t('interactive.attack')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={active?.id === f.id ? 'bg-white/5' : ''}>
                  <td className="px-4 py-3 font-mono text-xs text-dim" dir="ltr">
                    {f.id}
                  </td>
                  <td className="px-4 py-3">
                    <button type="button" className="text-start text-ink hover:text-accent" onClick={() => selectFinding(f.id)}>
                      <span className="block">{t(`interactive.findings.${f.id}.title`)}</span>
                      <span className="text-xs text-dim">
                        {t(`interactive.severity.${f.severity}`)} · <span dir="ltr">{f.asset}</span>
                      </span>
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full border border-[var(--line)] px-2 py-0.5 font-mono text-xs" dir="ltr">
                      {f.mitre[0]}
                    </span>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-4 py-8 text-center text-muted">
                    {t('interactive.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <aside className="lg:col-span-5" aria-live="polite">
          {active && (
            <div className="space-y-4 p-4">
              <p className="text-xs tracking-[0.14em] text-dim">{t('interactive.investigation')}</p>
              <h3 className="text-lg text-ink">{t(`interactive.findings.${active.id}.title`)}</h3>

              <div className="rounded-[12px] border border-accent/25 bg-accent/5 p-3">
                <p className="text-xs tracking-[0.14em] text-accent">{t('interactive.why')}</p>
                <p className="mt-1 text-sm text-ink">{t(`interactive.findings.${active.id}.why`)}</p>
              </div>

              {view === 'exec' ? (
                <p className="text-sm leading-relaxed text-muted">{t(`interactive.findings.${active.id}.exec`)}</p>
              ) : (
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-dim">{t('interactive.epss')}</dt>
                    <dd dir="ltr">{active.epss}</dd>
                  </div>
                  <div>
                    <dt className="text-dim">{t('interactive.kev')}</dt>
                    <dd>{active.kev ? t('interactive.kevYes') : t('interactive.kevNo')}</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-dim">{t('interactive.timeline')}</dt>
                    <dd className="font-mono text-xs">{t(`interactive.findings.${active.id}.timeline`)}</dd>
                  </div>
                </dl>
              )}

              <p className="text-sm text-muted">{t(`interactive.findings.${active.id}.evidence`)}</p>

              <div>
                <p className="text-xs tracking-[0.14em] text-ops">{t('interactive.remediation')}</p>
                <p className="mt-1 text-sm text-ink">{t(`interactive.findings.${active.id}.remediation`)}</p>
              </div>

              <div className="flex flex-wrap gap-1" aria-label="MITRE ATT&CK">
                {active.mitre.map((tech) => (
                  <span key={tech} className="rounded-full border border-[var(--line)] px-2 py-0.5 font-mono text-xs text-muted" dir="ltr">
                    {tech}
                  </span>
                ))}
              </div>

              <button
                type="button"
                className="min-h-11 text-sm text-accent"
                aria-expanded={pathOpen}
                onClick={() => {
                  setPathOpen((v) => !v)
                  interact('toggle_path')
                }}
              >
                {pathOpen ? t('interactive.hidePath') : t('interactive.showPath')}
              </button>
              {pathOpen && (
                <ol className="space-y-1 font-mono text-xs text-muted" dir="ltr">
                  <li>1. internet_exposed · {active.asset}</li>
                  <li>2. identity pivot · idp-core</li>
                  <li>3. crown_jewel · crown-db</li>
                </ol>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}
