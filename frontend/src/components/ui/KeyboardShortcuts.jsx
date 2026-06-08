import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const SHORTCUTS = [
  { keys: '?', desc: 'Show this help', global: true },
  { keys: '/', desc: 'Focus search', global: true },
  { keys: 'g h', desc: 'Go to Cockpit (home)' },
  { keys: 'g e', desc: 'Go to Engines' },
  { keys: 'g f', desc: 'Go to Findings' },
  { keys: 'g v', desc: 'Go to Vulnerability Intel' },
  { keys: 'g a', desc: 'Go to Agents' },
  { keys: 'g c', desc: 'Go to Clients' },
  { keys: 'g j', desc: 'Go to Jobs' },
  { keys: 'g s', desc: 'Go to System Configuration' },
  { keys: 'Esc', desc: 'Close dialogs / drawers', global: true },
]

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
      // Ignore when user is typing into an input/textarea/contenteditable.
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
    <div className="fixed inset-0 z-[9500] flex items-center justify-center p-4">
      <button
        type="button"
        onClick={() => setHelpOpen(false)}
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        aria-label="Close shortcuts"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="kbd-help-title"
        className="relative w-full max-w-lg rounded-2xl border border-white/15 bg-[#0b1120]/98 backdrop-blur-md p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between mb-4">
          <h2 id="kbd-help-title" className="text-base font-semibold text-white/90">
            Keyboard shortcuts
          </h2>
          <button
            type="button"
            onClick={() => setHelpOpen(false)}
            className="text-white/40 hover:text-white text-2xl leading-none"
            aria-label="Close"
          >×</button>
        </div>
        <table className="w-full text-[13px] font-mono">
          <tbody className="divide-y divide-white/5">
            {SHORTCUTS.map(({ keys, desc }) => (
              <tr key={keys}>
                <td className="py-2 pe-4 w-32">
                  {keys.split(' ').map((k, i) => (
                    <React.Fragment key={i}>
                      {i > 0 && <span className="text-white/30 mx-1">then</span>}
                      <kbd className="inline-block px-2 py-0.5 rounded border border-white/15 bg-white/5 text-cyan-200 text-[11px]">{k}</kbd>
                    </React.Fragment>
                  ))}
                </td>
                <td className="py-2 text-white/70">{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-[10px] text-white/35 mt-4">Press <kbd className="px-1 border border-white/15 rounded">Esc</kbd> to close.</p>
      </div>
    </div>
  )
}
