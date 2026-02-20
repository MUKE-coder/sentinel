'use client';

import { useState } from 'react';
import { Menu, Heart, Youtube, Linkedin, ExternalLink } from 'lucide-react';
import Sidebar, { MobileSidebar } from '@/components/Sidebar';

export default function DocsLayout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <button
        onClick={() => setSidebarOpen(true)}
        className="lg:hidden mb-4 p-2 rounded-lg border border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <Menu size={18} />
      </button>

      <MobileSidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex gap-10">
        <Sidebar />
        <main className="min-w-0 flex-1 prose-docs">
          {children}

          <hr className="my-12" />
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pb-8 not-prose text-sm text-gray-500">
            <div className="flex items-center gap-1.5">
              Built with <Heart size={14} className="text-red-500 fill-red-500" /> by{' '}
              <a
                href="https://jb.desishub.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="font-semibold text-gray-700 dark:text-gray-300 hover:text-sentinel-500 dark:hover:text-sentinel-400 transition-colors"
              >
                JB
              </a>
            </div>
            <div className="flex items-center gap-3">
              <a href="https://www.youtube.com/@JBWEBDEVELOPER" target="_blank" rel="noopener noreferrer" aria-label="YouTube" className="hover:text-red-500 transition-colors">
                <Youtube size={16} />
              </a>
              <a href="https://www.linkedin.com/in/muke-johnbaptist-95bb82198/" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" className="hover:text-blue-600 transition-colors">
                <Linkedin size={16} />
              </a>
              <a href="https://jb.desishub.com/" target="_blank" rel="noopener noreferrer" aria-label="Portfolio" className="hover:text-sentinel-500 transition-colors">
                <ExternalLink size={16} />
              </a>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
