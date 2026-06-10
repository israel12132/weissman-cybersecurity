import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Command, Keyboard, Navigation, Search, X } from 'lucide-react'

const SHORTCUTS = [
  { keys: '?', desc: 'Show this help', global: true, section: 'general' },
  { keys: '/', desc: 'Focus search', global: true, section: 'general' },
  { keys: 'g h', desc: 'Go to Cockpit (home)', section: 'nav' },
  { keys: 'g e', desc: 'Go to Engines', section: 'nav' },
  { keys: 'g f', desc: 'Go to Findings', section: 'nav' },
  { keys: 'g v', desc: 'Go to Vulnerability Intel', section: 'nav' },
  { keys: 'g a', desc: 'Go to Agents', section: 'nav' },
  { keys: 'g c', desc: 'Go to Clients', section: 'nav' },
  { keys: 'g j', desc: 'Go to Jobs', section: 'nav' },
  { keys: 'g q', desc: 'Go to Ask Weissman', section: 'nav' },
  { keys: 'g p', desc: 'Go to SOAR Playbooks', section: 'nav' },
  { keys: 'g s', desc: 'Go to System Configuration', section: 'nav' },
  { keys: 'Esc', desc: 'Close dialogs / drawers', global: true, section: 'general' },
]

const SECTIONS = [
  { id: 'general', label: 'General', Icon: Command },
  { id: 'nav', label: 'Navigation', Icon: Navigation },
]

function Kbd({ children }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.65rem] px-2 py-1 rounded-md border border-white/12 bg-gradient-to-b from-white/[0.08] to-white/[0.03] text-cyan-200/90 text-[11px] font-mono shadow-[0_1px_0_rgba(255,255,255,0.06),inset_0_1px_0_rgba(255,255,255,0.04)]">
      {children}
    </kbd>
  )
}

/**
 * Global keyboard-shortcut handler. Listens for "g + <letter>" sequences for navigation and
 * single-key shortcuts (?, /). Shows a help overlay on '?'.
 *
 * Mount once near the router root.
 */
export default function KeyboardShortcuts() {
  const navigate = useNavigate()
  const [helpOpen, setHelpOpen] = useState(false)

  useEffect(() => {
    let lastG = 0
    const onKey = (e) => {
      const tag = (e.target?.tagName || '').toLowerCase()
      const isInput = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable
      if (isInput && e.key !== 'Escape' && e.key !== '?') return

      if (e.key === 'Escape') {
        setHelpOpen(false)
        return
      }
      if (e.key === '?' && !isInput) {
        e.preventDefault()
        setHelpOpen((v) => !v)
        return
      }
      if (e.key === '/' && !isInput) {
        e.preventDefault()
        const el = document.querySelector('input[type="search"], input[placeholder*="earch" i]')
        if (el) el.focus()
        return
      }
      const now = Date.now()
      if (e.key === 'g' && !isInput) {
        lastG = now
        return
      }
      if (now - lastG < 1500 && !isInput) {
        const dest = {
          h: '/',
          e: '/engines',
          f: '/findings',
          v: '/vuln-intel',
          a: '/agents',
          c: '/clients',
          j: '/jobs',
          q: '/ask',
          p: '/playbooks',
          s: '/system-config',
        }[e.key]
        if (dest) {
          e.preventDefault()
          lastG = 0
          navigate(dest)
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [navigate])

  if (!helpOpen) return null

  return (
    <div className="fixed inset-0 z-[9500] flex items-center justify-center p-4 animate-fade-in">
      <button
        type="button"
        onClick={() => setHelpOpen(false)}
        className="absolute inset-0 bg-black/75 backdrop-blur-md"
        aria-label="Close shortcuts"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="kbd-help-title"
        className="relative w-full max-w-xl rounded-2xl border border-white/12 bg-[#0a0f1a]/97 backdrop-blur-xl shadow-[0_24px_80px_rgba(0,0,0,0.55)] overflow-hidden animate-slide-up"
      >
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent" aria-hidden="true" />

        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-white/6">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-9 h-9 rounded-lg border border-cyan-500/20 bg-cyan-500/10">
              <Keyboard className="w-4 h-4 text-cyan-400" strokeWidth={2} aria-hidden="true" />
            </span>
            <div>
              <h2 id="kbd-help-title" className="text-base font-semibold text-white/92">
                Keyboard shortcuts
              </h2>
              <p className="text-[11px] text-white/40 mt-0.5">Press <Kbd>?</Kbd> anytime to toggle</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setHelpOpen(false)}
            className="p-2 rounded-lg text-white/40 hover:text-white/90 hover:bg-white/6 transition-colors"
            style={{ transitionDuration: 'var(--duration-fast)' }}
            aria-label="Close"
          >
            <X className="w-4 h-4" strokeWidth={2.5} />
          </button>
        </div>

        <div className="px-6 py-4 max-h-[min(60vh,28rem)] overflow-y-auto custom-scroll space-y-5">
          {SECTIONS.map(({ id, label, Icon }) => {
            const rows = SHORTCUTS.filter((s) => s.section === id)
            if (rows.length === 0) return null
            return (
              <section key={id}>
                <div className="flex items-center gap-2 mb-2.5">
                  <Icon className="w-3.5 h-3.5 text-cyan-400/70" strokeWidth={2} aria-hidden="true" />
                  <h3 className="text-[10px] font-mono uppercase tracking-[0.18em] text-white/35">{label}</h3>
                </div>
                <div className="rounded-xl border border-white/6 divide-y divide-white/5 overflow-hidden">
                  {rows.map(({ keys, desc }) => (
                    <div key={keys} className="flex items-center gap-4 px-4 py-2.5 hover:bg-white/[0.02] transition-colors" style={{ transitionDuration: 'var(--duration-fast)' }}>
                      <div className="flex items-center gap-1.5 shrink-0 min-w-[7.5rem]">
                        {keys.split(' ').map((k, i) => (
                          <React.Fragment key={i}>
                            {i > 0 && <span className="text-[10px] text-white/25 font-mono">then</span>}
                            <Kbd>{k}</Kbd>
                          </React.Fragment>
                        ))}
                      </div>
                      <span className="text-[13px] text-white/72">{desc}</span>
                    </div>
                  ))}
                </div>
              </section>
            )
          })}
        </div>

        <div className="px-6 py-3.5 border-t border-white/6 bg-white/[0.02] flex items-center justify-between gap-3 text-[10px] text-white/35 font-mono">
          <span className="flex items-center gap-1.5">
            <Search className="w-3 h-3 opacity-60" aria-hidden="true" />
            <span><Kbd>/</Kbd> focuses global search</span>
          </span>
          <span><Kbd>Esc</Kbd> to close</span>
        </div>
      </div>
    </div>
  )
}
