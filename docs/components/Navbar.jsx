'use client';

import Link from 'next/link';
import { useState } from 'react';
import { Menu, X, Github, BookOpen, Shield } from 'lucide-react';
import ThemeToggle from './ThemeToggle';
import Search from './Search';

export default function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <nav className="sticky top-0 z-50 w-full border-b border-gray-200 dark:border-gray-800 bg-white/80 dark:bg-gray-950/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            <Link href="/" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-sentinel-400 to-sentinel-600 flex items-center justify-center">
                <Shield size={16} className="text-white" />
              </div>
              <span className="font-bold text-lg tracking-tight">Sentinel</span>
            </Link>

            <div className="hidden md:flex items-center gap-6">
              <Link
                href="/docs/getting-started"
                className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors flex items-center gap-1.5"
              >
                <BookOpen size={14} />
                Docs
              </Link>
              <Link
                href="/docs/api-reference"
                className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                API
              </Link>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:block">
              <Search />
            </div>
            <ThemeToggle />
            <a
              href="https://github.com/MUKE-coder/sentinel"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              aria-label="GitHub"
            >
              <Github size={18} className="text-gray-600 dark:text-gray-400" />
            </a>
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              {mobileOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>
      </div>

      {mobileOpen && (
        <div className="md:hidden border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 p-4">
          <div className="mb-3 sm:hidden">
            <Search />
          </div>
          <div className="space-y-2">
            <Link
              href="/docs/getting-started"
              onClick={() => setMobileOpen(false)}
              className="block px-3 py-2 rounded-lg text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-900"
            >
              Documentation
            </Link>
            <Link
              href="/docs/api-reference"
              onClick={() => setMobileOpen(false)}
              className="block px-3 py-2 rounded-lg text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-900"
            >
              API Reference
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
