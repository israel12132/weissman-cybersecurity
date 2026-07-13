import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Command, Search, Zap, CornerDownLeft, Clock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch } from '../lib/apiBase';
import { PRIMARY_NAV, NAV_GROUPS, canAccessNavItem } from '../lib/appNav';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import Button from './ui/Button'
import useFocusTrap from '../hooks/useFocusTrap'

const RECENTS_KEY = 'weissman_palette_recents';
const RECENTS_MAX = 6;

function readRecents() {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENTS_KEY) || '[]');
    return Array.isArray(raw) ? raw.filter((p) => typeof p === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * GlobalSearch — command palette (Ctrl/Cmd+K).
 *
 * Two result tiers, fully keyboard-navigable (↑/↓/Enter):
 *   1. Instant client-side navigation to any RBAC-accessible app route (no
 *      network round-trip), sourced from the single appNav registry.
 *   2. Server content search via GET /api/search?q= (findings, engines, …).
 */
export default function GlobalSearch() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { session, logout } = useAuth();
  const { toggleTheme, isLight } = useTheme();
  const { pathname } = useLocation();
  const [recents, setRecents] = useState(readRecents);
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const listRef = useRef(null);
  const dialogRef = useRef(null);
  useFocusTrap(dialogRef, isOpen);

  // Flat, RBAC-filtered route registry — the source for instant navigation.
  const navRoutes = useMemo(() => {
    const flat = [
      ...PRIMARY_NAV,
      ...NAV_GROUPS.flatMap((g) => g.items),
    ];
    const seen = new Set();
    return flat
      .filter((item) => canAccessNavItem(item, session))
      .filter((item) => {
        if (seen.has(item.to)) return false;
        seen.add(item.to);
        return true;
      })
      .map((item) => ({
        type: 'navigate',
        to: item.to,
        icon: item.icon || '→',
        title: t(item.labelKey),
      }));
  }, [session, t]);

  // Record each visited route (most-recent-first) so the idle palette can offer
  // "jump back" targets. Only known, accessible routes are surfaced later.
  useEffect(() => {
    if (!pathname) return;
    setRecents((prev) => {
      const next = [pathname, ...prev.filter((p) => p !== pathname)].slice(0, RECENTS_MAX);
      try { localStorage.setItem(RECENTS_KEY, JSON.stringify(next)); } catch { /* storage may be unavailable */ }
      return next;
    });
  }, [pathname]);

  const routeByPath = useMemo(() => {
    const m = new Map();
    for (const r of navRoutes) m.set(r.to, r);
    return m;
  }, [navRoutes]);

  const recentResults = useMemo(() => (
    recents
      .filter((p) => p !== pathname && routeByPath.has(p))
      .map((p) => ({ ...routeByPath.get(p), recent: true }))
      .slice(0, 5)
  ), [recents, pathname, routeByPath]);

  const localResults = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      // Idle: recents first, then quick-nav suggestions (deduped).
      const recentPaths = new Set(recentResults.map((r) => r.to));
      const quick = navRoutes.filter((r) => !recentPaths.has(r.to)).slice(0, 7 - recentResults.length);
      return [...recentResults, ...quick];
    }
    return navRoutes
      .filter((r) => r.title.toLowerCase().includes(q) || r.to.toLowerCase().includes(q))
      .slice(0, 8);
  }, [navRoutes, query, recentResults]);

  // Global command actions (shown only when the query matches — keeps idle clean).
  const actions = useMemo(() => [
    {
      type: 'action',
      icon: isLight ? '🌙' : '☀️',
      title: isLight ? t('components.globalSearch.action_theme_dark') : t('components.globalSearch.action_theme_light'),
      run: toggleTheme,
    },
    {
      type: 'action',
      icon: '🚪',
      title: t('components.globalSearch.action_signout'),
      run: () => logout?.(),
    },
  ], [isLight, toggleTheme, logout, t]);

  const actionResults = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return actions.filter((a) => a.title.toLowerCase().includes(q));
  }, [actions, query]);

  const combined = useMemo(
    () => [...localResults, ...actionResults, ...results],
    [localResults, actionResults, results],
  );

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen((v) => !v);
      }
      if (e.key === 'Escape') setIsOpen(false);
    };
    // Lets a visible affordance (e.g. the header search button) open the palette.
    const handleOpenEvent = () => setIsOpen(true);
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('weissman:open-command-palette', handleOpenEvent);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('weissman:open-command-palette', handleOpenEvent);
    };
  }, []);

  // Reset selection whenever the candidate list changes.
  useEffect(() => { setActiveIndex(0); }, [query, results.length, isOpen]);

  useEffect(() => {
    if (!query.trim() || query.trim().length < 2) {
      setResults([]);
      return undefined;
    }
    const ctrl = new AbortController();
    const tmr = setTimeout(async () => {
      setLoading(true);
      try {
        const r = await apiFetch(`/api/search?q=${encodeURIComponent(query.trim())}`, {
          signal: ctrl.signal,
        });
        const d = await r.json().catch(() => ({}));
        setResults(Array.isArray(d.results) ? d.results : []);
      } catch {
        if (!ctrl.signal.aborted) setResults([]);
      } finally {
        if (!ctrl.signal.aborted) setLoading(false);
      }
    }, 200);
    return () => {
      clearTimeout(tmr);
      ctrl.abort();
    };
  }, [query]);

  const goTo = useCallback((result) => {
    if (!result) return;
    if (result.type === 'action') {
      setIsOpen(false);
      setQuery('');
      result.run?.();
      return;
    }
    const path = result.to
      || result.path
      || (result.type === 'engine' && result.id ? `/engines/${result.id}` : '/');
    setIsOpen(false);
    setQuery('');
    navigate(path.startsWith('/') ? path : `/${path}`);
  }, [navigate]);

  const onInputKeyDown = useCallback((e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, Math.max(0, combined.length - 1)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      goTo(combined[activeIndex]);
    }
  }, [combined, activeIndex, goTo]);

  // Keep the highlighted row scrolled into view.
  useEffect(() => {
    if (!isOpen || !listRef.current) return;
    const el = listRef.current.querySelector(`[data-idx="${activeIndex}"]`);
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' });
  }, [activeIndex, isOpen]);

  if (!isOpen) return null;

  const showQuickNav = !query.trim();

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4 bg-[var(--scrim)] backdrop-blur-sm"
        onClick={() => setIsOpen(false)}
      >
        <motion.div
          initial={{ scale: 0.95, y: -20 }}
          animate={{ scale: 1, y: 0 }}
          exit={{ scale: 0.95, y: -20 }}
          className="w-full max-w-2xl bg-[var(--bg-elevated)] backdrop-blur-xl border border-[var(--border-strong)] rounded-2xl shadow-2xl overflow-hidden"
          onClick={(e) => e.stopPropagation()}
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-label={t('components.globalSearch.placeholder')}
        >
          <div className="flex items-center gap-3 p-4 border-b border-[var(--border-default)]">
            <Search className="w-5 h-5 text-[var(--text-muted)]" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder={t('components.globalSearch.placeholder')}
              className="flex-1 bg-transparent text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none text-lg"
              autoFocus
              role="combobox"
              aria-expanded="true"
              aria-controls="global-search-listbox"
              aria-activedescendant={combined.length ? `gs-opt-${activeIndex}` : undefined}
            />
            <kbd className="px-2 py-1 bg-[var(--row-hover-bg)] rounded text-xs text-[var(--text-muted)]">Esc</kbd>
          </div>

          <div className="max-h-[60vh] overflow-y-auto" ref={listRef} id="global-search-listbox" role="listbox">
            {showQuickNav && (
              <div className="px-4 pt-3 pb-1 text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                {t('components.globalSearch.quickNav')}
              </div>
            )}
            {combined.length === 0 ? (
              loading && query.length >= 2 ? (
                <div className="p-8 text-center text-[var(--text-muted)]">{t('components.globalSearch.searching')}</div>
              ) : query.length >= 2 ? (
                <div className="p-8 text-center text-[var(--text-muted)]">
                  {t('components.globalSearch.noResults', { query })}
                </div>
              ) : (
                <div className="p-8 text-center text-[var(--text-muted)]">
                  <Command className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  {t('components.globalSearch.startTyping')}
                </div>
              )
            ) : (
              <div className="divide-y divide-[var(--border-subtle)]">
                {combined.map((result, index) => {
                  const active = index === activeIndex;
                  const isNav = result.type === 'navigate';
                  return (
                    <Button variant="unstyled"
                      key={`${result.type}-${result.to || result.id || result.path || index}`}
                      type="button"
                      id={`gs-opt-${index}`}
                      data-idx={index}
                      role="option"
                      aria-selected={active}
                      className={`w-full flex items-center gap-3 p-4 transition-colors text-left ${
                        active ? 'bg-cyan-500/15' : 'hover:bg-[var(--row-hover-bg)]'
                      }`}
                      onClick={() => goTo(result)}
                      onMouseEnter={() => setActiveIndex(index)}
                    >
                      <span className="text-2xl">{result.icon || (isNav ? '→' : '🔎')}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-[var(--text-primary)] truncate">{result.title}</div>
                        <div className="text-xs text-[var(--text-muted)] capitalize flex items-center gap-1">
                          {result.recent && <Clock className="w-3 h-3" aria-hidden="true" />}
                          {isNav
                            ? (result.recent ? t('components.globalSearch.recent') : t('components.globalSearch.navigate'))
                            : result.type === 'action'
                              ? t('components.globalSearch.command')
                              : result.type}
                        </div>
                      </div>
                      {active ? (
                        <CornerDownLeft className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <Zap className="w-4 h-4 text-[var(--text-disabled)]" />
                      )}
                    </Button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex items-center justify-between p-3 border-t border-[var(--border-default)] bg-[var(--bg-2)] text-xs text-[var(--text-muted)]">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 bg-[var(--row-hover-bg)] rounded">↑↓</kbd> {t('components.globalSearch.navigateHint')}
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 bg-[var(--row-hover-bg)] rounded">Enter</kbd> {t('components.globalSearch.select')}
              </span>
            </div>
            <span>{t('components.globalSearch.brand')}</span>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

/** Open the command palette from anywhere (e.g. a header button). */
export function openCommandPalette() {
  document.dispatchEvent(new CustomEvent('weissman:open-command-palette'));
}

export function useGlobalSearch() {
  const [isOpen, setIsOpen] = useState(false);

  return {
    isOpen,
    open: () => setIsOpen(true),
    close: () => setIsOpen(false),
    toggle: () => setIsOpen((prev) => !prev),
  };
}
