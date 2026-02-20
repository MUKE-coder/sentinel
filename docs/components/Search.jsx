'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Search as SearchIcon, X, ArrowRight, Command } from 'lucide-react';
import { searchIndex } from '@/lib/docs';

export default function Search() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [selected, setSelected] = useState(0);
  const inputRef = useRef(null);
  const router = useRouter();

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(true);
      }
      if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (open) {
      inputRef.current?.focus();
    } else {
      setQuery('');
      setResults([]);
      setSelected(0);
    }
  }, [open]);

  const handleSearch = useCallback((value) => {
    setQuery(value);
    setSelected(0);
    if (!value.trim()) {
      setResults([]);
      return;
    }

    const terms = value.toLowerCase().split(/\s+/);
    const scored = searchIndex
      .map((item) => {
        const haystack = `${item.title} ${item.content} ${item.section}`.toLowerCase();
        let score = 0;
        for (const term of terms) {
          if (item.title.toLowerCase().includes(term)) score += 10;
          if (haystack.includes(term)) score += 1;
        }
        return { ...item, score };
      })
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 8);

    setResults(scored);
  }, []);

  const navigate = (href) => {
    router.push(href);
    setOpen(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelected((s) => Math.min(s + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelected((s) => Math.max(s - 1, 0));
    } else if (e.key === 'Enter' && results[selected]) {
      navigate(results[selected].href);
    }
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-sm text-gray-500 dark:text-gray-400 w-64"
      >
        <SearchIcon size={14} />
        <span className="flex-1 text-left">Search docs...</span>
        <kbd className="hidden sm:flex items-center gap-0.5 text-[10px] font-mono text-gray-400 dark:text-gray-500 bg-gray-200 dark:bg-gray-800 px-1.5 py-0.5 rounded">
          <Command size={10} /> K
        </kbd>
      </button>

      {open && (
        <div className="fixed inset-0 z-[100]">
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <div className="fixed top-[15vh] left-1/2 -translate-x-1/2 w-full max-w-xl">
            <div className="bg-white dark:bg-gray-900 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">
              <div className="flex items-center gap-3 px-4 border-b border-gray-200 dark:border-gray-800">
                <SearchIcon size={16} className="text-gray-400 flex-shrink-0" />
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => handleSearch(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Search documentation..."
                  className="flex-1 py-3 bg-transparent outline-none text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-400"
                />
                {query && (
                  <button onClick={() => handleSearch('')}>
                    <X size={14} className="text-gray-400 hover:text-gray-600" />
                  </button>
                )}
                <kbd
                  className="text-[10px] font-mono text-gray-400 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded cursor-pointer"
                  onClick={() => setOpen(false)}
                >
                  ESC
                </kbd>
              </div>

              {results.length > 0 ? (
                <ul className="max-h-80 overflow-y-auto py-2">
                  {results.map((result, i) => (
                    <li key={result.href}>
                      <button
                        onClick={() => navigate(result.href)}
                        onMouseEnter={() => setSelected(i)}
                        className={`w-full flex items-center justify-between px-4 py-2.5 text-left text-sm transition-colors ${
                          i === selected
                            ? 'bg-sentinel-50 dark:bg-sentinel-950/50 text-sentinel-600 dark:text-sentinel-400'
                            : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800'
                        }`}
                      >
                        <div>
                          <p className="font-medium">{result.title}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-500">{result.section}</p>
                        </div>
                        {i === selected && <ArrowRight size={14} />}
                      </button>
                    </li>
                  ))}
                </ul>
              ) : query ? (
                <div className="px-4 py-8 text-center text-sm text-gray-500">
                  No results for &ldquo;{query}&rdquo;
                </div>
              ) : (
                <div className="px-4 py-8 text-center text-sm text-gray-500">
                  Start typing to search...
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
