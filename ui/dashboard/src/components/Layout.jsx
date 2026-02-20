import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const navItems = [
  { to: '/sentinel/ui', label: 'Dashboard', icon: '◉' },
  { to: '/sentinel/ui/threats', label: 'Threats', icon: '⚠' },
  { to: '/sentinel/ui/actors', label: 'Actors', icon: '◎' },
  { to: '/sentinel/ui/ip-management', label: 'IP Mgmt', icon: '⊘' },
  { to: '/sentinel/ui/performance', label: 'Performance', icon: '◈' },
  { to: '/sentinel/ui/users', label: 'Users', icon: '◇' },
  { to: '/sentinel/ui/alerts', label: 'Alerts', icon: '◆' },
  { to: '/sentinel/ui/audit', label: 'Audit', icon: '◫' },
  { to: '/sentinel/ui/waf', label: 'WAF', icon: '◈' },
  { to: '/sentinel/ui/rate-limits', label: 'Rate Limits', icon: '◒' },
  { to: '/sentinel/ui/analytics', label: 'Analytics', icon: '◔' },
  { to: '/sentinel/ui/reports', label: 'Reports', icon: '◧' },
  { to: '/sentinel/ui/ai-insights', label: 'AI Insights', icon: '⬡' },
];

export default function Layout() {
  const { logout } = useAuth();

  return (
    <div className="min-h-screen bg-[#0a0f1e] flex">
      {/* Sidebar */}
      <aside className="w-56 bg-[#0d1526] border-r border-[#1e2d4a] flex flex-col shrink-0">
        <div className="p-4 border-b border-[#1e2d4a]">
          <h1 className="text-[#00d4ff] text-xl font-bold tracking-wider">SENTINEL</h1>
          <p className="text-[#8892a0] text-xs mt-1">Security Dashboard</p>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/sentinel/ui'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
                  isActive
                    ? 'bg-[#1e2d4a] text-[#00d4ff]'
                    : 'text-[#8892a0] hover:text-[#e0e0e0] hover:bg-[#0a0f1e]'
                }`
              }
            >
              <span className="text-base">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-[#1e2d4a]">
          <button
            onClick={logout}
            className="w-full px-3 py-2 text-sm text-[#8892a0] hover:text-[#ff2d55] hover:bg-[#0a0f1e] rounded transition-colors text-left"
          >
            Logout
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
