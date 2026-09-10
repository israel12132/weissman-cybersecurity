import { useI18n } from '../i18n'

/** Static Command Center chrome — original product UI, not a live tenant. */
export function CommandCenterMock() {
  const { t } = useI18n()
  return (
    <figure className="surface overflow-hidden shadow-[var(--shadow)]">
      <figcaption className="flex items-center justify-between border-b border-[var(--line)] bg-[#0d1218] px-3 py-2">
        <span className="font-mono text-[10px] tracking-[0.16em] text-dim">{t('visual.ccCaption')}</span>
        <span className="inline-flex items-center gap-2 font-mono text-[10px] text-ops">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ops" />
          {t('visual.live')}
        </span>
      </figcaption>
      <div className="grid md:grid-cols-12" dir="ltr">
        <div className="border-b border-[var(--line)] p-3 md:col-span-7 md:border-b-0 md:border-e">
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.14em] text-dim">Findings</p>
          <ul className="space-y-1.5 text-xs">
            <Row id="F-0988" sev="P1" title="idp-core · T1133" active />
            <Row id="F-1042" sev="P2" title="edge-web · T1190" />
            <Row id="F-0771" sev="P3" title="laptop-soc-12 · T1046" />
            <Row id="F-0610" sev="—" title="ot-plc-lab · agent_required" muted />
          </ul>
        </div>
        <div className="space-y-3 p-4 md:col-span-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-accent">Investigation</p>
          <p className="text-sm text-ink">{t('interactive.findings.F-0988.title')}</p>
          <p className="text-xs leading-relaxed text-muted">{t('interactive.findings.F-0988.evidence')}</p>
          <p className="rounded-[10px] border border-ops/30 bg-ops/10 px-3 py-2 text-xs text-ops">
            {t('interactive.findings.F-0988.remediation')}
          </p>
        </div>
      </div>
    </figure>
  )
}

function Row({
  id,
  sev,
  title,
  active,
  muted,
}: {
  id: string
  sev: string
  title: string
  active?: boolean
  muted?: boolean
}) {
  return (
    <li
      className={`flex items-center justify-between rounded-[10px] px-2 py-2 ${
        active ? 'bg-accent/10 text-ink' : muted ? 'text-dim' : 'text-muted'
      }`}
    >
      <span className="font-mono text-[11px]">{id}</span>
      <span className="truncate px-2">{title}</span>
      <span className={`font-mono text-[10px] ${active ? 'text-danger' : 'text-dim'}`}>{sev}</span>
    </li>
  )
}
