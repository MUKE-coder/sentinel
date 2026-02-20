'use client';

import { useState } from 'react';
import { Menu } from 'lucide-react';
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
        </main>
      </div>
    </div>
  );
}
