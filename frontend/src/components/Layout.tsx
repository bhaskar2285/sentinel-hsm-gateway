import { NavLink, Outlet } from 'react-router-dom';
import HsmStatusWidget from './HsmStatusWidget';
import {
  KeyRound,
  PlusCircle,
  Download,
  Cpu,
  Play,
  Server,
  ScrollText,
  Terminal,
  ShieldCheck,
  LogOut,
  Lock,
} from 'lucide-react';

const navSections = [
  {
    label: 'Vault',
    items: [
      { to: '/keys',         label: 'Locate',       code: null,    icon: KeyRound },
      { to: '/keys/new',     label: 'Generate RSA', code: 'EI/EJ', icon: PlusCircle },
      { to: '/keys/new-sym', label: 'Generate Sym', code: 'A0/A1', icon: PlusCircle },
      { to: '/keys/import',  label: 'Import Key',   code: 'GI/GJ', icon: Download },
    ],
  },
  {
    label: 'Crypto',
    items: [
      { to: '/wizard',  label: 'Walkthrough', code: 'CHAIN', icon: Play },
      { to: '/crypto',  label: 'Decrypt',     code: 'M2/M3', icon: Cpu },
      { to: '/console', label: 'Raw Wire',    code: null,    icon: Terminal },
    ],
  },
  {
    label: 'Fleet',
    items: [
      { to: '/pools', label: 'HSM Pools', code: null, icon: Server },
      { to: '/audit', label: 'Audit Log', code: null, icon: ScrollText },
    ],
  },
  {
    label: 'Admin',
    items: [
      { to: '/admin/banks', label: 'Banks',  code: 'FIID', icon: ShieldCheck },
      { to: '/admin/rbac',  label: 'Access', code: 'SAM',  icon: ShieldCheck },
    ],
  },
];

export default function Layout() {
  const user = (() => {
    try { return JSON.parse(localStorage.getItem('sentinel.user') ?? 'null'); }
    catch { return null; }
  })();

  return (
    <div className="flex h-full bg-slate-50">
      <aside className="w-64 border-r border-slate-200 bg-white flex flex-col">
        {/* brand */}
        <div className="px-5 py-5 border-b border-slate-200 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center shadow-sm">
            <Lock size={15} className="text-sky-400" strokeWidth={2.5} />
          </div>
          <div>
            <div className="wordmark text-[15px] leading-tight">Sentinel</div>
            <div className="text-[10px] uppercase tracking-[0.12em] text-slate-500 font-medium">HSM Console</div>
          </div>
        </div>

        {/* nav */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-5">
          {navSections.map((sect) => (
            <div key={sect.label}>
              <div className="px-3 mb-1.5 text-[10px] uppercase tracking-[0.12em] font-semibold text-slate-400">
                {sect.label}
              </div>
              <div className="space-y-0.5">
                {sect.items.map(({ to, label, code, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end
                    className={({ isActive }) =>
                      `nav-link ${isActive ? 'nav-link-active' : ''}`
                    }
                  >
                    <Icon size={15} strokeWidth={2} />
                    <span className="flex-1">{label}</span>
                    {code && <span className="chip-mono">{code}</span>}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* user footer */}
        <div className="border-t border-slate-200 p-3">
          {user && (
            <div className="px-3 py-2 mb-1.5">
              <div className="text-xs font-medium text-slate-900 truncate">{user.loginname}</div>
              <div className="text-[10px] text-slate-500 font-mono">
                {user.bankCode ?? '—'} · staff#{user.staffId ?? '—'}
              </div>
            </div>
          )}
          <button
            onClick={() => {
              localStorage.removeItem('sentinel.jwt');
              localStorage.removeItem('sentinel.user');
              window.location.assign('/login');
            }}
            className="nav-link w-full"
          >
            <LogOut size={15} strokeWidth={2} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur px-8 py-3 flex items-center justify-end gap-3">
          <HsmStatusWidget />
        </header>
        <div className="px-8 py-8 animate-fade-up">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
