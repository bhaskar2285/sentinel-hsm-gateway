import { NavLink, Outlet } from 'react-router-dom';
import HsmStatusWidget from './HsmStatusWidget';
import {
  KeyRound,
  PlusCircle,
  Download,
  Cpu,
  Server,
  ScrollText,
  Terminal,
  ShieldCheck,
  LogOut,
} from 'lucide-react';

const nav = [
  { to: '/keys',         label: 'Locate',       code: null,    icon: KeyRound },
  { to: '/keys/new',     label: 'Generate RSA', code: 'EI/EJ', icon: PlusCircle },
  { to: '/keys/new-sym', label: 'Generate Sym', code: 'A0/A1', icon: PlusCircle },
  { to: '/keys/import',  label: 'Import Key',   code: 'GI/GJ', icon: Download },
  { to: '/crypto',       label: 'Decrypt',      code: 'M2/M3', icon: Cpu },
  { to: '/pools',        label: 'Pools',        code: null,    icon: Server },
  { to: '/audit',        label: 'Audit',        code: null,    icon: ScrollText },
  { to: '/console',      label: 'Raw',          code: null,    icon: Terminal },
  { to: '/admin/banks',  label: 'Banks',        code: 'FIID',  icon: ShieldCheck },
  { to: '/admin/rbac',   label: 'RBAC',         code: 'SAM',   icon: ShieldCheck },
];

export default function Layout() {
  return (
    <div className="flex h-full">
      <aside className="w-56 border-r border-slate-200 bg-white shadow-sm p-4 flex flex-col">
        <div className="mb-6">
          <div className="text-lg font-semibold tracking-tight">Sentinel</div>
          <div className="text-xs text-slate-500">HSM Console</div>
        </div>
        <nav className="flex-1 space-y-1">
          {nav.map(({ to, label, code, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded-md text-sm ${
                  isActive
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`
              }
            >
              <Icon size={16} />
              <span className="flex-1">{label}</span>
              {code && <span className="text-[10px] font-mono text-slate-500">[{code}]</span>}
            </NavLink>
          ))}
        </nav>
        <button
          onClick={() => {
            localStorage.removeItem('sentinel.jwt');
            window.location.assign('/login');
          }}
          className="flex items-center gap-2 px-3 py-2 rounded-md text-sm text-slate-600 hover:bg-slate-100"
        >
          <LogOut size={16} /> Sign out
        </button>
      </aside>
      <main className="flex-1 overflow-auto">
        <header className="border-b border-slate-200 bg-white shadow-sm px-6 py-3 flex items-center justify-end">
          <HsmStatusWidget />
        </header>
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
