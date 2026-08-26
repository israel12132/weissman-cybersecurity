import { useMemo, useState } from 'react'

type Severity = 'critical' | 'high' | 'medium' | 'info'

type Finding = {
  id: string
  title: string
  asset: string
  severity: Severity
  mitre: string
  epss: string
  kev: boolean
  timeline: string
  evidence: string
  remediation: string
}

const SAMPLE: Finding[] = [
  {
    id: 'F-1042',
    title: 'Blind SSRF candidate awaiting callback',
    asset: 'edge-web-01',
    severity: 'high',
    mitre: 'T1190',
    epss: '0.84',
    kev: false,
    timeline: 'probe planted · listener idle',
    evidence: 'OAST token embedded. No HTTP/DNS callback yet — not marked verified.',
    remediation: 'Wait for correlation, then restrict egress from the app tier.',
  },
  {
    id: 'F-0988',
    title: 'Internet-exposed admin path on idp-core',
    asset: 'idp-core',
    severity: 'critical',
    mitre: 'T1133',
    epss: '0.91',
    kev: true,
    timeline: 'live probe · 2 recurrences',
    evidence: 'HTTP 200 on an in-scope admin route. KEV-listed CVE attached at persist.',
    remediation: 'Remove public exposure; require SSO; rotate credentials.',
  },
  {
    id: 'F-0771',
    title: 'New listening port on workstation',
    asset: 'laptop-soc-12',
    severity: 'medium',
    mitre: 'T1046',
    epss: '—',
    kev: false,
    timeline: 'UEBA · out of learning window',
    evidence: 'Port never seen in this hour-of-week bucket after 24 samples.',
    remediation: 'Confirm expected software; isolate if unexplained.',
  },
  {
    id: 'F-0610',
    title: 'Advisory: agent not enrolled',
    asset: 'ot-plc-lab',
    severity: 'info',
    mitre: 'T1046',
    epss: '—',
    kev: false,
    timeline: 'catalog · agent_required',
    evidence: 'Host engines labelled empty until the Weissman agent is online.',
    remediation: 'Install the agent if this host is in written scope.',
  },
]

const FILTERS: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'info']

export function InteractiveProduct() {
  const [sev, setSev] = useState<(typeof FILTERS)[number]>('all')
  const [asset, setAsset] = useState('all')
  const [open, setOpen] = useState<string>(SAMPLE[1].id)
  const [pathOpen, setPathOpen] = useState(true)

  const assets = useMemo(() => ['all', ...new Set(SAMPLE.map((f) => f.asset))], [])
  const rows = SAMPLE.filter((f) => (sev === 'all' || f.severity === sev) && (asset === 'all' || f.asset === asset))
  const active = rows.find((f) => f.id === open) ?? rows[0]

  return (
    <div className="surface overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] px-4 py-3">
        <div>
          <p className="text-sm font-medium text-ink">Command Center walkthrough</p>
          <p className="text-xs uppercase tracking-[0.14em] text-risk">Illustrative — not live tenant data</p>
        </div>
        <span className="inline-flex items-center gap-2 text-xs text-ops">
          <span className="h-2 w-2 animate-pulse rounded-full bg-ops" />
          sample event stream
        </span>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-[var(--line)] px-4 py-3">
        <div role="group" aria-label="Severity filter" className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              className={`min-h-11 rounded-[10px] px-3 text-sm ${sev === f ? 'bg-accent text-[#041016]' : 'text-muted hover:text-ink'}`}
              aria-pressed={sev === f}
              onClick={() => setSev(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <label className="ml-auto flex min-h-11 items-center gap-2 text-sm text-muted">
          Asset
          <select
            className="min-h-11 rounded-[10px] border border-[var(--line)] bg-deep px-2 text-ink"
            value={asset}
            onChange={(e) => setAsset(e.target.value)}
          >
            {assets.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid lg:grid-cols-12">
        <div className="border-b border-[var(--line)] lg:col-span-7 lg:border-b-0 lg:border-r">
          <table className="w-full text-left text-sm">
            <thead className="text-[0.7rem] uppercase tracking-[0.12em] text-dim">
              <tr>
                <th className="px-4 py-2 font-medium">ID</th>
                <th className="px-4 py-2 font-medium">Finding</th>
                <th className="px-4 py-2 font-medium">ATT&CK</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={active?.id === f.id ? 'bg-white/5' : ''}>
                  <td className="px-4 py-3 font-mono text-xs text-dim">{f.id}</td>
                  <td className="px-4 py-3">
                    <button type="button" className="text-left text-ink hover:text-accent" onClick={() => setOpen(f.id)}>
                      <span className="block">{f.title}</span>
                      <span className="text-xs capitalize text-dim">
                        {f.severity} · {f.asset}
                      </span>
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full border border-[var(--line)] px-2 py-0.5 font-mono text-xs">{f.mitre}</span>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-4 py-8 text-center text-muted">
                    No sample rows for this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <aside className="lg:col-span-5" aria-live="polite">
          {active && (
            <div className="space-y-4 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-dim">Investigation</p>
              <h3 className="text-lg text-ink">{active.title}</h3>
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-dim">EPSS</dt>
                  <dd>{active.epss}</dd>
                </div>
                <div>
                  <dt className="text-dim">KEV</dt>
                  <dd>{active.kev ? 'listed' : 'no'}</dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-dim">Timeline</dt>
                  <dd className="font-mono text-xs">{active.timeline}</dd>
                </div>
              </dl>
              <p className="text-sm text-muted">{active.evidence}</p>
              <div>
                <p className="text-xs uppercase tracking-[0.14em] text-ops">Suggested remediation</p>
                <p className="mt-1 text-sm text-ink">{active.remediation}</p>
              </div>
              <button
                type="button"
                className="min-h-11 text-sm text-accent"
                aria-expanded={pathOpen}
                onClick={() => setPathOpen((v) => !v)}
              >
                {pathOpen ? 'Hide' : 'Expand'} sample attack path
              </button>
              {pathOpen && (
                <ol className="space-y-1 font-mono text-xs text-muted">
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
