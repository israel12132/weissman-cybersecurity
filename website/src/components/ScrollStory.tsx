import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../i18n'
import { Reveal } from './Reveal'

const STAGES = ['challenge', 'transform', 'outcome'] as const
type Stage = (typeof STAGES)[number]

export function ScrollStory() {
  const { t } = useI18n()
  const [stage, setStage] = useState<Stage>('challenge')
  const refs = useRef<Record<Stage, HTMLElement | null>>({
    challenge: null,
    transform: null,
    outcome: null,
  })

  useEffect(() => {
    const els = STAGES.map((id) => refs.current[id]).filter((n): n is HTMLElement => Boolean(n))
    if (!els.length) return
    const io = new IntersectionObserver(
      (entries) => {
        const vis = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
        const id = vis?.target.getAttribute('data-stage') as Stage | null
        if (id && STAGES.includes(id)) setStage(id)
      },
      { rootMargin: '-35% 0px -45% 0px', threshold: [0.2, 0.5, 0.8] },
    )
    els.forEach((el) => io.observe(el))
    return () => io.disconnect()
  }, [])

  return (
    <div className="grid items-start gap-10 lg:grid-cols-12">
      <div className="space-y-16 lg:col-span-5">
        {STAGES.map((id) => (
          <Reveal key={id}>
            <article
              ref={(node) => {
                refs.current[id] = node
              }}
              data-stage={id}
              className={`transition duration-slow ${stage === id ? 'opacity-100' : 'opacity-70'}`}
            >
              <p className="font-mono text-xs text-accent">{t(`home.story.${id}.label`)}</p>
              <h3 className="mt-3 display text-2xl text-ink md:text-3xl">{t(`home.story.${id}.title`)}</h3>
              <p className="mt-4 text-sm leading-relaxed text-muted md:text-base">{t(`home.story.${id}.body`)}</p>
            </article>
          </Reveal>
        ))}
      </div>
      <div className="lg:col-span-7">
        <div className="lg:sticky lg:top-[calc(var(--nav-h)+4.5rem)]">
          <StoryVisual stage={stage} />
        </div>
      </div>
    </div>
  )
}

function StoryVisual({ stage }: { stage: Stage }) {
  const { t } = useI18n()
  const noise = stage === 'challenge'
  const path = stage === 'transform'
  const clear = stage === 'outcome'

  return (
    <div className="overflow-hidden rounded-[14px] border border-[var(--line)] bg-[#0a0e14] shadow-[var(--shadow)]">
      <div className="flex items-center justify-between border-b border-[var(--line)] px-3 py-2">
        <span className="font-mono text-[10px] tracking-[0.14em] text-dim">{t(`home.story.${stage}.visual`)}</span>
        <span className="font-mono text-[10px] text-accent">{t(`home.story.${stage}.label`)}</span>
      </div>
      <div dir="ltr" className="aspect-[16/10]">
        <svg viewBox="0 0 640 400" className="h-full w-full" aria-hidden>
          <rect width="640" height="400" fill="#0a1018" />
          <g stroke="#1c2836" strokeWidth="0.5" opacity="0.5">
            {Array.from({ length: 14 }, (_, i) => (
              <line key={i} x1={46 * i} y1="0" x2={46 * i} y2="400" />
            ))}
          </g>
          <g fill="none" stroke="#e8b86d" strokeWidth="1.2" opacity={noise ? 0.7 : 0.12} className={noise ? 'theater-dash' : undefined}>
            <path d="M80 60 C 160 40, 200 180, 120 260" />
            <path d="M200 80 C 280 20, 340 200, 280 320" />
            <path d="M360 50 C 420 120, 500 80, 560 180" />
            <path d="M90 300 C 220 240, 300 340, 480 280" />
          </g>
          <g
            fill="none"
            stroke="#22d3ee"
            strokeWidth="2.4"
            opacity={path || clear ? 1 : 0.08}
            className={path || clear ? 'theater-dash' : undefined}
          >
            <path d="M90 90 L 220 160 L 360 120 L 520 210" />
          </g>
          {['edge', 'vpn', 'idp', 'db'].map((label, i) => {
            const xs = [90, 220, 360, 520]
            const ys = [90, 160, 120, 210]
            const hot = path || clear
            return (
              <g key={label}>
                <circle cx={xs[i]} cy={ys[i]} r="8" fill={hot ? '#22d3ee' : '#4a5563'} />
                <text x={xs[i]} y={ys[i] + 24} textAnchor="middle" fill="#c8c2b6" fontSize="11" fontFamily="JetBrains Mono, monospace">
                  {label}
                </text>
              </g>
            )
          })}
          {clear && (
            <g>
              <rect x="360" y="250" width="240" height="92" rx="8" fill="#101820" stroke="#3ee0b2" strokeOpacity="0.5" />
              <text x="376" y="278" fill="#3ee0b2" fontSize="11" fontFamily="JetBrains Mono, monospace">
                1 operational view
              </text>
              <text x="376" y="302" fill="#f4efe6" fontSize="13" fontFamily="Inter, Heebo, sans-serif">
                P1 · idp-core · KEV
              </text>
              <text x="376" y="322" fill="#9aa3ad" fontSize="11" fontFamily="JetBrains Mono, monospace">
                isolate · rotate · verify
              </text>
            </g>
          )}
          {noise &&
            [0, 1, 2, 3, 4].map((i) => (
              <rect
                key={i}
                x={40 + i * 110}
                y={28}
                width="88"
                height="18"
                rx="4"
                fill="#e8b86d"
                opacity={0.25 + (i % 3) * 0.12}
              />
            ))}
        </svg>
      </div>
    </div>
  )
}
