import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import useFocusTrap from '../../hooks/useFocusTrap'
import Button from './Button'

const SHORTCUT_DEFS = [
  { keys: '?', descKey: 'shortcuts.show_help', global: true },
  { keys: '/', descKey: 'shortcuts.focus_search', global: true },
  { keys: 'g h', descKey: 'shortcuts.go_cockpit' },
  { keys: 'g e', descKey: 'shortcuts.go_engines' },
  { keys: 'g f', descKey: 'shortcuts.go_findings' },
  { keys: 'g v', descKey: 'shortcuts.go_vuln_intel' },
  { keys: 'g a', descKey: 'shortcuts.go_agents' },
  { keys: 'g c', descKey: 'shortcuts.go_clients' },
  { keys: 'g j', descKey: 'shortcuts.go_jobs' },
  { keys: 'g q', descKey: 'shortcuts.go_ask' },
  { keys: 'g p', descKey: 'shortcuts.go_playbooks' },
  { keys: 'g s', descKey: 'shortcuts.go_system_config' },
  { keys: 'Esc', descKey: 'shortcuts.close_dialogs', global: true },
]

/**
 * Global keyboard-shortcut handler. Listens for "g + <letter>" sequences for navigation and
 * single-key shortcuts (?, /). Shows a help overlay on '?'.
 */
export default function KeyboardShortcuts() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [helpOpen, setHelpOpen] = useState(false)
  const dialogRef = useRef(null)
  useFocusTrap(dialogRef, helpOpen)

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
    <div className="fixed inset-0 z-[9500] flex items-center justify-center p-4">
      <Button variant="unstyled"
        type="button"
        onClick={() => setHelpOpen(false)}
        className="absolute inset-0 bg-[var(--bg-1)] backdrop-blur-sm"
        aria-label={t('a11y.close_shortcuts')}
      />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="kbd-help-title"
        className="relative w-full max-w-lg rounded-2xl border border-[var(--border-strong)] bg-[var(--bg-elevated)] backdrop-blur-md p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between mb-4">
          <h2 id="kbd-help-title" className="text-base font-semibold text-[var(--text-primary)]">
            {t('a11y.keyboard_shortcuts')}
          </h2>
          <Button variant="unstyled"
            type="button"
            onClick={() => setHelpOpen(false)}
            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] text-2xl leading-none"
            aria-label={t('a11y.close')}
          >×</Button>
        </div>
        <table className="w-full text-[13px] font-mono data-grid">
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {SHORTCUT_DEFS.map(({ keys, descKey }) => (
              <tr key={keys}>
                <td className="py-2 pe-4 w-32">
                  {keys.split(' ').map((k, i) => (
                    <React.Fragment key={i}>
                      {i > 0 && <span className="text-[var(--text-disabled)] mx-1">{t('a11y.then')}</span>}
                      <kbd className="inline-block px-2 py-0.5 rounded border border-[var(--border-strong)] bg-[var(--row-hover-bg)] text-cyan-200 text-[11px]">{k}</kbd>
                    </React.Fragment>
                  ))}
                </td>
                <td className="py-2 text-[var(--text-secondary)]">{t(descKey)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-[10px] text-[var(--text-muted)] mt-4">
          {t('a11y.press_esc_to_close')}
        </p>
      </div>
    </div>
  )
}
