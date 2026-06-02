import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { NavLink, Outlet } from 'react-router-dom';
import HsmStatusWidget from './HsmStatusWidget';
import { KeyRound, PlusCircle, Download, Cpu, Play, Server, ScrollText, Terminal, ShieldCheck, LogOut, Lock, } from 'lucide-react';
const navSections = [
    {
        label: 'Vault',
        items: [
            { to: '/keys', label: 'Locate', code: null, icon: KeyRound },
            { to: '/keys/new', label: 'Generate RSA', code: 'EI/EJ', icon: PlusCircle },
            { to: '/keys/new-sym', label: 'Generate Sym', code: 'A0/A1', icon: PlusCircle },
            { to: '/keys/import', label: 'Import Key', code: 'GI/GJ', icon: Download },
        ],
    },
    {
        label: 'Crypto',
        items: [
            { to: '/wizard', label: 'Walkthrough', code: 'CHAIN', icon: Play },
            { to: '/crypto', label: 'Decrypt', code: 'M2/M3', icon: Cpu },
            { to: '/console', label: 'Raw Wire', code: null, icon: Terminal },
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
            { to: '/admin/banks', label: 'Banks', code: 'FIID', icon: ShieldCheck },
            { to: '/admin/rbac', label: 'Access', code: 'SAM', icon: ShieldCheck },
        ],
    },
];
export default function Layout() {
    const user = (() => {
        try {
            return JSON.parse(localStorage.getItem('sentinel.user') ?? 'null');
        }
        catch {
            return null;
        }
    })();
    return (_jsxs("div", { className: "flex h-full bg-slate-50", children: [_jsxs("aside", { className: "w-64 border-r border-slate-200 bg-white flex flex-col", children: [_jsxs("div", { className: "px-5 py-5 border-b border-slate-200 flex items-center gap-2.5", children: [_jsx("div", { className: "w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center shadow-sm", children: _jsx(Lock, { size: 15, className: "text-sky-400", strokeWidth: 2.5 }) }), _jsxs("div", { children: [_jsx("div", { className: "wordmark text-[15px] leading-tight", children: "Sentinel" }), _jsx("div", { className: "text-[10px] uppercase tracking-[0.12em] text-slate-500 font-medium", children: "HSM Console" })] })] }), _jsx("nav", { className: "flex-1 overflow-y-auto p-3 space-y-5", children: navSections.map((sect) => (_jsxs("div", { children: [_jsx("div", { className: "px-3 mb-1.5 text-[10px] uppercase tracking-[0.12em] font-semibold text-slate-400", children: sect.label }), _jsx("div", { className: "space-y-0.5", children: sect.items.map(({ to, label, code, icon: Icon }) => (_jsxs(NavLink, { to: to, end: true, className: ({ isActive }) => `nav-link ${isActive ? 'nav-link-active' : ''}`, children: [_jsx(Icon, { size: 15, strokeWidth: 2 }), _jsx("span", { className: "flex-1", children: label }), code && _jsx("span", { className: "chip-mono", children: code })] }, to))) })] }, sect.label))) }), _jsxs("div", { className: "border-t border-slate-200 p-3", children: [user && (_jsxs("div", { className: "px-3 py-2 mb-1.5", children: [_jsx("div", { className: "text-xs font-medium text-slate-900 truncate", children: user.loginname }), _jsxs("div", { className: "text-[10px] text-slate-500 font-mono", children: [user.bankCode ?? '—', " \u00B7 staff#", user.staffId ?? '—'] })] })), _jsxs("button", { onClick: () => {
                                    localStorage.removeItem('sentinel.jwt');
                                    localStorage.removeItem('sentinel.user');
                                    window.location.assign('/login');
                                }, className: "nav-link w-full", children: [_jsx(LogOut, { size: 15, strokeWidth: 2 }), _jsx("span", { children: "Sign out" })] })] })] }), _jsxs("main", { className: "flex-1 overflow-auto", children: [_jsx("header", { className: "sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur px-8 py-3 flex items-center justify-end gap-3", children: _jsx(HsmStatusWidget, {}) }), _jsx("div", { className: "px-8 py-8 animate-fade-up", children: _jsx(Outlet, {}) })] })] }));
}
