import {
  Activity,
  Bell,
  BookOpen,
  Building2,
  ClipboardList,
  FileText,
  Gauge,
  HeartPulse,
  KeyRound,
  LogOut,
  Radar,
  Search,
  Server,
  Settings,
  ShieldAlert,
  Users,
} from 'lucide-react';
import { NavLink, Outlet } from 'react-router-dom';
import { TenantSelector } from '../components/TenantSelector';
import { useAuth } from '../hooks/useAuth';

const nav = [
  { to: '/', label: 'Overview', icon: Gauge },
  { to: '/logs', label: 'Log Explorer', icon: Search },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/incidents', label: 'Incidents', icon: ClipboardList },
  { to: '/rules', label: 'Detection Rules', icon: Radar },
  { to: '/sources', label: 'Log Sources', icon: Server },
  { to: '/threat-intel', label: 'Threat Intel', icon: KeyRound },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/audit', label: 'Audit Trail', icon: BookOpen },
  { to: '/users', label: 'Users', icon: Users },
  { to: '/tenants', label: 'Tenants', icon: Building2 },
  { to: '/health', label: 'System Health', icon: HeartPulse },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function AppLayout() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen bg-base-950 text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-slate-800 bg-base-900 lg:block">
        <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-5">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/30">
            <Activity size={21} />
          </span>
          <div>
            <p className="text-sm font-semibold">Mini SIEM</p>
            <p className="text-xs text-slate-500">Security Operations</p>
          </div>
        </div>
        <nav className="scrollbar h-[calc(100vh-4rem)] overflow-y-auto px-3 py-4">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `mb-1 flex items-center gap-3 rounded-md px-3 py-2 text-sm transition ${isActive ? 'bg-cyan-500/12 text-cyan-200 ring-1 ring-cyan-500/20' : 'text-slate-400 hover:bg-base-800 hover:text-slate-100'}`
              }
            >
              <item.icon size={18} />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="lg:pl-72">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between gap-3 border-b border-slate-800 bg-base-950/95 px-4 backdrop-blur lg:px-6">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-slate-100">{user?.full_name}</p>
            <p className="truncate text-xs text-slate-500">{user?.role.replace('_', ' ')}</p>
          </div>
          <div className="flex items-center gap-2">
            <TenantSelector />
            <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Notifications">
              <Bell size={18} />
            </button>
            <button onClick={logout} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-red-200" title="Logout">
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main className="px-4 py-5 lg:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
