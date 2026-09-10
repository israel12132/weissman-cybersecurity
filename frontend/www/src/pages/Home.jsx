import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import LivePulse from '../components/LivePulse'
import EngineConstellation from '../components/EngineConstellation'
import { fetchEngineCatalog } from '../lib/liveApi'

const LAYER_IDS = ['offensive', 'cloud', 'identity', 'ot', 'ai', 'remediation']

export default function Home() {
  const { t } = useTranslation()
  const [ids, setIds] = useState([])

  useEffect(() => {
    let cancelled = false
    fetchEngineCatalog()
      .then((d) => {
        if (cancelled) return
        const list = (d.engines || []).filter((e) => e.kind === 'real_probe').map((e) => e.id)
        setIds(list)
      })
      .catch(() => {
        setIds([])
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <>
      <section className="relative isolate overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          aria-hidden
          style={{
            background:
              'radial-gradient(ellipse 80% 60% at 12% -10%, rgba(34,211,238,0.16), transparent 55%), radial-gradient(ellipse 70% 50% at 92% 8%, rgba(14,165,233,0.12), transparent 50%), radial-gradient(ellipse 90% 70% at 50% 110%, rgba(15,23,42,0.95), transparent 60%)',
          }}
        />
        <EngineConstellation
          ids={ids}
          className="pointer-events-none absolute inset-0 h-full w-full opacity-70"
        />
        <div className="relative mx-auto max-w-6xl px-5 pb-24 pt-16 sm:pt-28">
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-300/80">{t('home.kicker')}</p>
          <h1 className="mt-5 max-w-3xl font-display text-4xl font-semibold leading-[1.05] tracking-tight text-white sm:text-6xl lg:text-[4.15rem]">
            {t('home.title_1')} <span className="bg-gradient-to-r from-cyan-300 to-sky-500 bg-clip-text text-transparent">{t('home.title_accent')}</span>
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-white/55">{t('home.lead')}</p>
          <div className="mt-9 flex flex-wrap gap-3">
            <a href="/login" className="rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-[#041018] shadow-[0_0_32px_rgba(34,211,238,0.22)] hover:bg-cyan-300">
              {t('home.cta_enter')}
            </a>
            <Link to="/signup" className="rounded-xl border border-white/15 px-5 py-3 text-sm text-white/80 hover:border-cyan-400/40">
              {t('home.cta_trial')}
            </Link>
            <Link to="/contact" className="rounded-xl px-5 py-3 text-sm text-white/50 hover:text-white">
              {t('home.cta_demo')}
            </Link>
          </div>
          <LivePulse className="mt-16" />
        </div>
      </section>

      <section className="border-t border-white/10 px-5 py-20">
        <div className="mx-auto max-w-6xl">
          <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('home.why_kicker')}</p>
          <h2 className="mt-3 max-w-3xl font-display text-3xl font-semibold text-white">{t('home.why_title')}</h2>
          <p className="mt-4 max-w-3xl text-white/55">{t('home.why_lead')}</p>
        </div>
      </section>

      <section className="border-t border-white/10 px-5 py-20">
        <div className="mx-auto max-w-6xl">
          <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('home.layers_kicker')}</p>
          <h2 className="mt-3 font-display text-3xl font-semibold">{t('home.layers_title')}</h2>
          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {LAYER_IDS.map((id) => (
              <Link
                key={id}
                to={`/platform/${id}`}
                className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 transition hover:border-cyan-400/30"
              >
                <h3 className="font-display text-lg text-white">{t(`layers.${id}.title`)}</h3>
                <p className="mt-2 text-sm leading-relaxed text-white/50">{t(`layers.${id}.body`)}</p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-white/10 px-5 py-20">
        <div className="mx-auto max-w-6xl">
          <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('home.how_kicker')}</p>
          <h2 className="mt-3 font-display text-3xl font-semibold">{t('home.how_title')}</h2>
          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {['1', '2', '3', '4'].map((n) => (
              <div key={n} className="rounded-2xl border border-white/10 p-6">
                <div className="font-mono text-cyan-300/80">{n.padStart(2, '0')}</div>
                <h3 className="mt-2 font-display text-lg">{t(`steps.${n}.title`)}</h3>
                <p className="mt-2 text-sm text-white/50">{t(`steps.${n}.body`)}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-white/10 px-5 py-20">
        <div className="mx-auto max-w-3xl text-center">
          <h2 className="font-display text-3xl font-semibold">{t('home.cta_band_title')}</h2>
          <p className="mt-3 text-white/50">{t('home.cta_band_lead')}</p>
          <div className="mt-8 flex justify-center gap-3">
            <a href="/login" className="rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-[#041018]">{t('home.cta_enter')}</a>
            <Link to="/signup" className="rounded-xl border border-white/15 px-5 py-3 text-sm">{t('home.cta_trial')}</Link>
          </div>
        </div>
      </section>
    </>
  )
}
