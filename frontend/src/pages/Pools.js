import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
export default function Pools() {
    const pools = useQuery({
        queryKey: ['pools'],
        queryFn: () => api.get('/pools').then((r) => r.data),
        refetchInterval: 5000,
    });
    const hsms = useQuery({
        queryKey: ['hsms'],
        queryFn: () => api.get('/hsms').then((r) => r.data),
        refetchInterval: 5000,
    });
    return (_jsxs("div", { className: "space-y-6", children: [_jsx("h1", { className: "text-2xl font-semibold", children: "HSM Pools" }), _jsxs("section", { children: [_jsx("h2", { className: "text-lg mb-3 text-slate-700", children: "Pools" }), _jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-3", children: (pools.data ?? []).map((p) => {
                            const poolNodes = (hsms.data ?? []).filter((n) => n.poolId === p.id);
                            const upCount = poolNodes.filter((n) => n.health === 'UP').length;
                            return (_jsx("div", { className: "rounded-lg border border-slate-200 bg-white shadow-sm p-4", children: _jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("div", { children: [_jsx("div", { className: "text-sm font-medium", children: p.name }), _jsxs("div", { className: "text-xs text-slate-500", children: [p.vendor, " \u00B7 ", p.lbStrategy] })] }), _jsxs("span", { className: upCount > 0 ? 'badge-ok' : 'badge-err', children: [upCount, "/", poolNodes.length, " UP"] })] }) }, p.id));
                        }) })] }), _jsxs("section", { children: [_jsx("h2", { className: "text-lg mb-3 text-slate-700", children: "Nodes" }), _jsx("div", { className: "overflow-hidden rounded-lg border border-slate-200", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "bg-slate-50/80 text-slate-600", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left px-4 py-2", children: "Status" }), _jsx("th", { className: "text-left px-4 py-2", children: "Vendor" }), _jsx("th", { className: "text-left px-4 py-2", children: "Host" }), _jsx("th", { className: "text-left px-4 py-2", children: "Port" }), _jsx("th", { className: "text-left px-4 py-2", children: "Dir" }), _jsx("th", { className: "text-left px-4 py-2", children: "Weight" }), _jsx("th", { className: "text-left px-4 py-2", children: "Last Seen" })] }) }), _jsx("tbody", { children: (hsms.data ?? []).map((n) => (_jsxs("tr", { className: "border-t border-slate-200 hover:bg-slate-50", children: [_jsx("td", { className: "px-4 py-2", children: _jsx(StatusBadge, { health: n.health, enabled: n.enabled }) }), _jsx("td", { className: "px-4 py-2 font-mono text-xs", children: n.vendor }), _jsx("td", { className: "px-4 py-2 font-mono text-xs", children: n.host }), _jsx("td", { className: "px-4 py-2 font-mono text-xs", children: n.port }), _jsx("td", { className: "px-4 py-2", children: n.direction }), _jsx("td", { className: "px-4 py-2", children: n.weight }), _jsx("td", { className: "px-4 py-2 text-slate-500 text-xs", children: n.lastSeen ? new Date(n.lastSeen).toLocaleString() : '—' })] }, n.id))) })] }) })] })] }));
}
function StatusBadge({ health, enabled }) {
    if (!enabled) {
        return (_jsxs("span", { className: "inline-flex items-center gap-2 text-xs", children: [_jsx("span", { className: "w-2 h-2 rounded-full bg-slate-400" }), "DISABLED"] }));
    }
    const map = {
        UP: { dot: 'bg-emerald-500 shadow-[0_0_6px] rgb(16_185_129_/_0.6)', text: 'text-emerald-700', label: 'ONLINE' },
        DOWN: { dot: 'bg-rose-500 shadow-[0_0_6px] rgb(244_63_94_/_0.6)', text: 'text-rose-700', label: 'OFFLINE' },
        DRAINING: { dot: 'bg-amber-500', text: 'text-amber-700', label: 'DRAINING' },
        UNKNOWN: { dot: 'bg-slate-400 animate-pulse', text: 'text-slate-600', label: 'PROBING' },
    };
    const s = map[health] ?? map.UNKNOWN;
    return (_jsxs("span", { className: `inline-flex items-center gap-2 text-xs font-medium ${s.text}`, children: [_jsx("span", { className: `w-2 h-2 rounded-full ${s.dot}` }), s.label] }));
}
