'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';
import { sidebarNav } from '@/lib/docs';

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden lg:block w-64 flex-shrink-0">
      <div className="sticky top-20 overflow-y-auto max-h-[calc(100vh-5rem)] pb-10 pr-4">
        <nav className="space-y-6">
          {sidebarNav.map((group) => (
            <div key={group.title}>
              <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 px-3">
                {group.title}
              </h4>
              <ul className="space-y-0.5">
                {group.items.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className={clsx(
                        'block px-3 py-1.5 rounded-lg text-sm transition-colors',
                        pathname === item.href
                          ? 'bg-sentinel-50 dark:bg-sentinel-950/50 text-sentinel-600 dark:text-sentinel-400 font-medium'
                          : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-900'
                      )}
                    >
                      {item.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </div>
    </aside>
  );
}

export function MobileSidebar({ open, onClose }) {
  const pathname = usePathname();

  if (!open) return null;

  return (
    <div className="lg:hidden fixed inset-0 z-50">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div className="fixed left-0 top-0 bottom-0 w-72 bg-white dark:bg-gray-950 p-6 overflow-y-auto">
        <nav className="space-y-6">
          {sidebarNav.map((group) => (
            <div key={group.title}>
              <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                {group.title}
              </h4>
              <ul className="space-y-0.5">
                {group.items.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onClose}
                      className={clsx(
                        'block px-3 py-1.5 rounded-lg text-sm transition-colors',
                        pathname === item.href
                          ? 'bg-sentinel-50 dark:bg-sentinel-950/50 text-sentinel-600 dark:text-sentinel-400 font-medium'
                          : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-900'
                      )}
                    >
                      {item.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </div>
    </div>
  );
}
