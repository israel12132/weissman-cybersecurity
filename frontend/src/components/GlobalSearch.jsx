import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Command, Search, Zap } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch } from '../lib/apiBase';

/**
 * GlobalSearch - Universal search with keyboard shortcuts (Ctrl+K)
 * Backed by GET /api/search?q=
 */
export default function GlobalSearch() {
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(true);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (!query.trim() || query.trim().length < 2) {
      setResults([]);
      return undefined;
    }
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
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
      clearTimeout(t);
      ctrl.abort();
    };
  }, [query]);

  const goTo = useCallback((result) => {
    const path = result.path || (result.type === 'engine' && result.id ? `/engines/${result.id}` : '/');
    setIsOpen(false);
    setQuery('');
    navigate(path.startsWith('/') ? path : `/${path}`);
  }, [navigate]);

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4 bg-black/60 backdrop-blur-sm"
        onClick={() => setIsOpen(false)}
      >
        <motion.div
          initial={{ scale: 0.95, y: -20 }}
          animate={{ scale: 1, y: 0 }}
          exit={{ scale: 0.95, y: -20 }}
          className="w-full max-w-2xl bg-gray-900/95 backdrop-blur-xl border border-white/20 rounded-2xl shadow-2xl overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center gap-3 p-4 border-b border-white/10">
            <Search className="w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search anything... (pages, engines, findings, clients)"
              className="flex-1 bg-transparent text-white placeholder-gray-500 outline-none text-lg"
              autoFocus
            />
            <kbd className="px-2 py-1 bg-white/10 rounded text-xs text-gray-400">Esc</kbd>
          </div>

          <div className="max-h-[60vh] overflow-y-auto">
            {loading && query.length >= 2 ? (
              <div className="p-8 text-center text-gray-500">Searching…</div>
            ) : results.length === 0 && query.length >= 2 ? (
              <div className="p-8 text-center text-gray-500">
                No results found for &quot;{query}&quot;
              </div>
            ) : results.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <Command className="w-8 h-8 mx-auto mb-2 opacity-50" />
                Start typing to search…
              </div>
            ) : (
              <div className="divide-y divide-white/5">
                {results.map((result, index) => (
                  <button
                    key={`${result.type}-${result.id || result.path || index}`}
                    type="button"
                    className="w-full flex items-center gap-3 p-4 hover:bg-white/5 transition-colors text-left"
                    onClick={() => goTo(result)}
                  >
                    <span className="text-2xl">{result.icon || '🔎'}</span>
                    <div className="flex-1">
                      <div className="text-sm font-medium text-white">{result.title}</div>
                      <div className="text-xs text-gray-500 capitalize">{result.type}</div>
                    </div>
                    <Zap className="w-4 h-4 text-gray-600" />
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="flex items-center justify-between p-3 border-t border-white/10 bg-white/5 text-xs text-gray-500">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 bg-white/10 rounded">Enter</kbd> Select
              </span>
            </div>
            <span>Weissman Global Search</span>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
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
