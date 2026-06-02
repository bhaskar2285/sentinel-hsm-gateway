import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
export default function Audit() {
    const [op, setOp] = useState('');
    const [userId, setUserId] = useState('');
    const [status, setStatus] = useState('');
    const [vendor, setVendor] = useState('');
    const [page, setPage] = useState(0);
    const size = 25;
    const { data, isLoading, refetch } = useQuery({
        queryKey: ['audit', op, userId, status, vendor, page],
        queryFn: async () => {
            const params = { page, size };
            if (op)
                params.op = op;
            if (userId)
                params.userId = userId;
            if (status)
                params.status = status;
            if (vendor)
                params.vendor = vendor;
            const r = await api.get('/audit', { params, baseURL: '/api/v1' });
            return r.data;
        },
    });
    return (_jsxs("div", { className: "space-y-4 max-w-6xl", children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Audit Trail" }), _jsx("p", { className: "text-xs text-slate-500", children: "SHA-256 request/response fingerprints. Raw bytes never persisted." }), _jsxs("div", { className: "grid grid-cols-4 gap-3 text-sm", children: [_jsx("input", { value: op, onChange: (e) => setOp(e.target.value), placeholder: "op (RSA_KEY_GEN\u2026)", className: "input" }), _jsx("input", { value: userId, onChange: (e) => setUserId(e.target.value), placeholder: "userId", className: "input" }), _jsxs("select", { value: status, onChange: (e) => setStatus(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 status \u2014" }), _jsx("option", { value: "OK", children: "OK" }), _jsx("option", { value: "ERROR", children: "ERROR" }), _jsx("option", { value: "TIMEOUT", children: "TIMEOUT" })] }), _jsxs("select", { value: vendor, onChange: (e) => setVendor(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 vendor \u2014" }), _jsx("option", { value: "THALES", children: "THALES" }), _jsx("option", { value: "UTIMACO", children: "UTIMACO" })] })] }), _jsx("button", { onClick: () => { setPage(0); refetch(); }, className: "rounded-md btn-primary", children: "Search" }), isLoading && _jsx("div", { className: "text-slate-500", children: "Loading\u2026" }), data && (_jsxs(_Fragment, { children: [_jsxs("div", { className: "text-xs text-slate-500", children: [data.totalElements, " rows"] }), _jsx("div", { className: "overflow-x-auto border border-slate-200 rounded-md", children: _jsxs("table", { className: "w-full text-xs", children: [_jsx("thead", { className: "bg-slate-50", children: _jsxs("tr", { className: "text-left text-slate-600", children: [_jsx("th", { className: "px-3 py-2", children: "Timestamp" }), _jsx("th", { className: "px-3 py-2", children: "User" }), _jsx("th", { className: "px-3 py-2", children: "Op" }), _jsx("th", { className: "px-3 py-2", children: "Vendor" }), _jsx("th", { className: "px-3 py-2", children: "Node" }), _jsx("th", { className: "px-3 py-2", children: "Status" }), _jsx("th", { className: "px-3 py-2", children: "Err" }), _jsx("th", { className: "px-3 py-2", children: "Latency" }), _jsx("th", { className: "px-3 py-2", children: "Req hash" }), _jsx("th", { className: "px-3 py-2", children: "Resp hash" })] }) }), _jsx("tbody", { children: data.content.map((r) => (_jsxs("tr", { className: "border-t border-slate-200", children: [_jsx("td", { className: "px-3 py-1.5 font-mono", children: r.ts }), _jsx("td", { className: "px-3 py-1.5", children: r.userId }), _jsx("td", { className: "px-3 py-1.5", children: r.op }), _jsx("td", { className: "px-3 py-1.5", children: r.vendor }), _jsx("td", { className: "px-3 py-1.5", children: r.hsmNodeId }), _jsx("td", { className: `px-3 py-1.5 ${r.status === 'OK' ? 'text-sky-600' : 'text-red-700'}`, children: r.status }), _jsx("td", { className: "px-3 py-1.5", children: r.errCode }), _jsxs("td", { className: "px-3 py-1.5", children: [r.latencyMs, "ms"] }), _jsxs("td", { className: "px-3 py-1.5 font-mono text-slate-500", title: r.requestHash, children: [r.requestHash?.slice(0, 12), "\u2026"] }), _jsxs("td", { className: "px-3 py-1.5 font-mono text-slate-500", title: r.responseHash, children: [r.responseHash?.slice(0, 12), "\u2026"] })] }, r.id))) })] }) }), _jsxs("div", { className: "flex gap-2 text-sm", children: [_jsx("button", { disabled: page === 0, onClick: () => setPage(page - 1), className: "rounded-md bg-slate-100 hover:bg-slate-200 disabled:opacity-40 px-3 py-1.5", children: "\u2190 Prev" }), _jsxs("span", { className: "text-slate-500", children: ["page ", page + 1] }), _jsx("button", { disabled: (page + 1) * size >= (data?.totalElements ?? 0), onClick: () => setPage(page + 1), className: "rounded-md bg-slate-100 hover:bg-slate-200 disabled:opacity-40 px-3 py-1.5", children: "Next \u2192" })] })] }))] }));
}
