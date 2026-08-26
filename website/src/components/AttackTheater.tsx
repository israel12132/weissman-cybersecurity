import { useCallback, useId, useState, type PointerEvent } from 'react'
import { useI18n } from '../i18n'
import { track } from '../lib/analytics'

type Phase = 'noise' | 'path' | 'priority'

/**
 * Original Weissman product scene: noisy findings → attributed attack path →
 * one prioritised response. Pointer parallax is subtle; no WebGL.
 */
export function AttackTheater() {
  const { t } = useI18n()
  const uid = useId().replace(/:/g, '')
  const [phase, setPhase] = useState<Phase>('priority')
  const [tilt, setTilt] = useState({ x: 0, y: 0 })

  const onMove = useCallback((e: PointerEvent<HTMLDivElement>) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const r = e.currentTarget.getBoundingClientRect()
    const nx = (e.clientX - r.left) / r.width - 0.5
    const ny = (e.clientY - r.top) / r.height - 0.5
    setTilt({ x: nx * 8, y: ny * 6 })
  }, [])

  const set = (next: Phase) => {
    setPhase(next)
    track('product_demo_interact', { surface: 'hero_theater', phase: next })
  }

  const noise = phase === 'noise'
  const path = phase === 'path'
  const prio = phase === 'priority'

  return (
    <div
      className="relative isolate overflow-hidden rounded-[14px] border border-[var(--line)] bg-[#0a0e14] shadow-[var(--shadow)]"
      onPointerMove={onMove}
      onPointerLeave={() => setTilt({ x: 0, y: 0 })}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[#0d1218] px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-ops" aria-hidden />
          <span className="font-mono text-[10px] tracking-[0.16em] text-dim">{t('interactive.badge')}</span>
        </div>
        <div className="flex gap-1" role="tablist" aria-label={t('hero.theaterTabs')}>
          {(
            [
              ['noise', 'hero.phaseNoise'],
              ['path', 'hero.phasePath'],
              ['priority', 'hero.phasePriority'],
            ] as const
          ).map(([id, key]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={phase === id}
              className={`min-h-11 rounded-[10px] px-2.5 py-1 font-mono text-[10px] tracking-wide transition duration-swift ${
                phase === id ? 'bg-accent/15 text-accent' : 'text-dim hover:text-ink'
              }`}
              onClick={() => set(id)}
            >
              {t(key)}
            </button>
          ))}
        </div>
      </div>

      <div className="relative aspect-[16/11] min-h-[280px] sm:min-h-[340px]">
        <div dir="ltr" className="h-full w-full">
          <svg
            viewBox="0 0 640 440"
            className="h-full w-full"
            role="img"
            aria-labelledby={`${uid}-title ${uid}-desc`}
            style={{
              transform: `translate3d(${tilt.x}px, ${tilt.y}px, 0)`,
              transition: 'transform 220ms var(--ease)',
            }}
          >
            <title id={`${uid}-title`}>{t('hero.theaterTitle')}</title>
            <desc id={`${uid}-desc`}>{t('hero.theaterDesc')}</desc>
            <defs>
              <linearGradient id={`${uid}-g`} x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#12202c" />
                <stop offset="100%" stopColor="#0a1018" />
              </linearGradient>
              <filter id={`${uid}-glow`} x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="3" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <rect width="640" height="440" fill={`url(#${uid}-g)`} />
            <g stroke="#1c2836" strokeWidth="0.5" opacity="0.55">
              {Array.from({ length: 16 }, (_, i) => (
                <line key={`v${i}`} x1={40 * i} y1="0" x2={40 * i} y2="440" />
              ))}
              {Array.from({ length: 11 }, (_, i) => (
                <line key={`h${i}`} x1="0" y1={40 * i} x2="640" y2={40 * i} />
              ))}
            </g>

            <g fill="#22d3ee" opacity={noise ? 0.35 : 0.12}>
              {[40, 90, 150, 210, 280, 340, 400, 470, 530, 590].map((x, i) => (
                <rect key={x} x={x} y={18 + (i % 3) * 4} width="18" height="3" rx="1" />
              ))}
            </g>

            <g fontFamily="JetBrains Mono, ui-monospace, monospace" fontSize="10" fill="#9aa3ad">
              <Node x={110} y={90} label="edge-web" hot={path || prio} />
              <Node x={250} y={160} label="vpn-gw" hot={path || prio} />
              <Node x={400} y={120} label="idp-core" hot={prio} />
              <Node x={520} y={220} label="crown-db" hot={prio} accent />
              <Node x={180} y={300} label="ep-214" muted={!noise} />
              <Node x={320} y={340} label="ep-088" muted={!noise} />
              <Node x={460} y={320} label="ep-041" muted />
            </g>

            <g
              fill="none"
              stroke="#e8b86d"
              strokeWidth="1"
              opacity={noise ? 0.55 : 0.08}
              className={noise ? 'theater-dash' : undefined}
            >
              <path d="M110 90 C 160 140, 200 200, 180 300" />
              <path d="M110 90 C 200 80, 280 200, 320 340" />
              <path d="M250 160 C 300 220, 380 280, 460 320" />
              <path d="M180 300 C 260 280, 340 240, 400 120" />
            </g>

            <g
              fill="none"
              stroke="#22d3ee"
              strokeWidth="2.2"
              filter={`url(#${uid}-glow)`}
              opacity={path || prio ? 1 : 0.12}
              className={path || prio ? 'theater-dash' : undefined}
            >
              <path d="M110 90 L 250 160 L 400 120 L 520 220" />
            </g>

            <g opacity={prio ? 1 : 0.15}>
              <rect
                x="368"
                y="248"
                width="248"
                height="86"
                rx="8"
                fill="#101820"
                stroke="#22d3ee"
                strokeOpacity="0.45"
              />
              <text x="384" y="272" fill="#22d3ee" fontFamily="JetBrains Mono, ui-monospace" fontSize="10">
                F-1042 · P1
              </text>
              <text x="384" y="292" fill="#f4efe6" fontFamily="Inter, Heebo, sans-serif" fontSize="12">
                Blind SSRF · OAST wait
              </text>
              <text x="384" y="312" fill="#9aa3ad" fontFamily="JetBrains Mono, ui-monospace" fontSize="10">
                T1190 · T1078 · T1552
              </text>
            </g>
          </svg>
        </div>

        <p className="pointer-events-none absolute bottom-3 start-3 end-3 font-mono text-[10px] leading-relaxed text-dim sm:text-[11px]">
          {noise ? t('hero.captionNoise') : path ? t('hero.captionPath') : t('hero.captionPriority')}
        </p>
      </div>
    </div>
  )
}

function Node({
  x,
  y,
  label,
  hot,
  accent,
  muted,
}: {
  x: number
  y: number
  label: string
  hot?: boolean
  accent?: boolean
  muted?: boolean
}) {
  const fill = accent ? '#22d3ee' : hot ? '#3ee0b2' : muted ? '#3a4554' : '#6b7785'
  return (
    <g>
      <circle cx={x} cy={y} r="7" fill={fill} opacity={muted ? 0.45 : 1} />
      <text x={x} y={y + 22} textAnchor="middle" fill={muted ? '#6b7785' : '#c8c2b6'}>
        {label}
      </text>
    </g>
  )
}
