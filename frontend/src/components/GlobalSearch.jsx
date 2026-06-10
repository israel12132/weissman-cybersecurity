import { useState, useEffect } from 'react';
import { Command, Search, Zap } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

/**
 * GlobalSearch - Universal search with keyboard shortcuts (Ctrl+K)
 *
 * Searches:
 * - Pages
 * - Engines
 * - Findings
 * - Clients
 * - Commands
 */
export default function GlobalSearch() {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  // Keyboard shortcut: Ctrl+K or Cmd+K
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

  // Search logic
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    // Simulate search (replace with actual API call)
    const mockResults = [
      { type: 'page', title: 'Dashboard', path: '/', icon: '📊' },
      { type: 'page', title: 'Findings', path: '/findings', icon: '🔍' },
      { type: 'engine', title: 'XSS Scanner', id: 'xss_scanner', icon: '⚡' },
      { type: 'client', title: 'Example Corp', id: '1', icon: '🏢' },
    ].filter((item) =>
      item.title.toLowerCase().includes(query.toLowerCase())
    );

    setResults(mockResults);
  }, [query]);

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
          {/* Search Input */}
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

          {/* Results */}
          <div className="max-h-[60vh] overflow-y-auto">
            {results.length === 0 && query ? (
              <div className="p-8 text-center text-gray-500">
                No results found for "{query}"
              </div>
            ) : results.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <Command className="w-8 h-8 mx-auto mb-2 opacity-50" />
                Start typing to search...
              </div>
            ) : (
              <div className="divide-y divide-white/5">
                {results.map((result, index) => (
                  <button
                    key={index}
                    className="w-full flex items-center gap-3 p-4 hover:bg-white/5 transition-colors text-left"
                    onClick={() => {
                      // Navigate to result
                      setIsOpen(false);
                    }}
                  >
                    <span className="text-2xl">{result.icon}</span>
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

          {/* Footer */}
          <div className="flex items-center justify-between p-3 border-t border-white/10 bg-white/5 text-xs text-gray-500">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 bg-white/10 rounded">↑↓</kbd> Navigate
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 bg-white/10 rounded">Enter</kbd> Select
              </span>
            </div>
            <span>Powered by Weissman Search</span>
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
