import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { PlusCircle, Search } from 'lucide-react';
import { keysApi } from '../api/keys';
import { api } from '../api/client';
export default function Locate() {
    const [label, setLabel] = useState('');
    const [keyType, setKeyType] = useState('');
    const { data, isLoading, error } = useQuery({
        queryKey: ['keys', label, keyType],
        queryFn: () => keysApi.list({ label: label || undefined, keyType: keyType || undefined }),
    });
    const { data: banks = [] } = useQuery({
        queryKey: ['admin', 'banks'],
        queryFn: async () => (await api.get('/admin/banks', { baseURL: '/api/v1' })).data,
    });
    const bankLabel = (id) => {
        if (!id)
            return null;
        const b = banks.find(x => x.recId === id);
        return b ? `${b.code}` : `#${id}`;
    };
    return (_jsxs("div", { className: "space-y-6 max-w-7xl", children: [_jsxs("div", { className: "flex items-end justify-between", children: [_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold tracking-tight", children: "Key Vault" }), _jsxs("p", { className: "text-sm text-slate-500 mt-1", children: ["All keys held under LMK. ", data?.length ?? 0, " entries."] })] }), _jsxs(Link, { to: "/keys/new", className: "btn-primary", children: [_jsx(PlusCircle, { size: 14 }), " New RSA Key"] })] }), _jsxs("div", { className: "flex gap-2", children: [_jsxs("div", { className: "relative flex-1", children: [_jsx(Search, { size: 14, className: "absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" }), _jsx("input", { value: label, onChange: (e) => setLabel(e.target.value), placeholder: "Search by label\u2026", className: "input pl-9" })] }), _jsxs("select", { value: keyType, onChange: (e) => setKeyType(e.target.value), className: "select max-w-[180px]", children: [_jsx("option", { value: "", children: "All types" }), _jsx("option", { children: "RSA" }), _jsx("option", { children: "AES" }), _jsx("option", { children: "3DES" }), _jsx("option", { children: "ZMK" }), _jsx("option", { children: "ZPK" }), _jsx("option", { children: "TMK" }), _jsx("option", { children: "TPK" }), _jsx("option", { children: "KBPK" }), _jsx("option", { children: "BDK" })] })] }), isLoading && _jsx("div", { className: "text-slate-500 text-sm", children: "Loading\u2026" }), error ? _jsxs("div", { className: "badge-err", children: ["Error: ", error.message] }) : null, _jsx("div", { className: "table-wrap", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "table-head", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left px-4 py-2.5", children: "Label" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Type" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Algo" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Bits" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "KCV" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Bank" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Status" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Created" })] }) }), _jsxs("tbody", { children: [(data ?? []).map((k) => (_jsxs("tr", { className: "table-row", children: [_jsx("td", { className: "px-4 py-2.5", children: _jsx(Link, { to: `/keys/${k.keyId}`, className: "text-sky-600 hover:text-sky-700 font-medium", children: k.label }) }), _jsx("td", { className: "px-4 py-2.5", children: _jsx("span", { className: "badge-mute", children: k.keyType }) }), _jsx("td", { className: "px-4 py-2.5 text-slate-600", children: k.algo }), _jsx("td", { className: "px-4 py-2.5 font-mono text-xs text-slate-600", children: k.keyLengthBits }), _jsx("td", { className: "px-4 py-2.5", children: _jsx("span", { className: "chip-mono", children: k.kcv ?? '—' }) }), _jsx("td", { className: "px-4 py-2.5", children: k.bankRecId
                                                ? _jsx("span", { className: "badge-info", children: bankLabel(k.bankRecId) })
                                                : _jsx("span", { className: "text-slate-400 text-xs", children: "\u2014" }) }), _jsx("td", { className: "px-4 py-2.5", children: _jsx("span", { className: k.status === 'ACTIVE' ? 'badge-ok' : 'badge-mute', children: k.status }) }), _jsx("td", { className: "px-4 py-2.5 text-slate-500 font-mono text-xs", children: new Date(k.createdAt).toISOString().slice(0, 16).replace('T', ' ') })] }, k.keyId))), data?.length === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 8, className: "px-4 py-10 text-center text-slate-500 text-sm", children: "No keys match. Try a different filter or generate one." }) }))] })] }) })] }));
}
