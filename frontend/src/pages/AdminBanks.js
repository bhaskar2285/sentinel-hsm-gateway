import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { api } from '../api/client';
export default function AdminBanks() {
    const qc = useQueryClient();
    const [selected, setSelected] = useState(null);
    const [draft, setDraft] = useState({ loginMethodType: 'DB', permissionMethodType: 'DB' });
    const banks = useQuery({
        queryKey: ['admin', 'banks'],
        queryFn: async () => (await api.get('/admin/banks', { baseURL: '/api/v1' })).data,
    });
    const branches = useQuery({
        queryKey: ['admin', 'banks', selected, 'branches'],
        queryFn: async () => (await api.get(`/admin/banks/${selected}/branches`, { baseURL: '/api/v1' })).data,
        enabled: !!selected,
    });
    const createBank = useMutation({
        mutationFn: async (b) => (await api.post('/admin/banks', b, { baseURL: '/api/v1' })).data,
        onSuccess: () => {
            toast.success('Bank created');
            qc.invalidateQueries({ queryKey: ['admin', 'banks'] });
            setDraft({ loginMethodType: 'DB', permissionMethodType: 'DB' });
        },
        onError: (e) => toast.error(e?.message ?? 'create failed'),
    });
    return (_jsxs("div", { className: "space-y-6 max-w-6xl", children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Banks & Branches" }), _jsx("p", { className: "text-xs text-slate-500", children: "ISC FIID master. Per-bank auth method (DB / LDAP / MSAD / OIDC)." }), _jsxs("div", { className: "grid grid-cols-2 gap-6", children: [_jsxs("div", { className: "space-y-2", children: [_jsx("h2", { className: "text-sm font-medium text-slate-700", children: "Existing" }), banks.isLoading && _jsx("div", { className: "text-slate-500 text-sm", children: "Loading\u2026" }), banks.data?.map((b) => (_jsxs("div", { onClick: () => setSelected(b.recId), className: `rounded-md border p-3 cursor-pointer text-sm ${selected === b.recId ? 'border-sky-600 bg-sky-50' : 'border-slate-200 hover:border-slate-300'}`, children: [_jsxs("div", { className: "flex justify-between items-baseline", children: [_jsx("div", { className: "font-medium", children: b.name }), _jsx("span", { className: "text-xs font-mono text-slate-500", children: b.code })] }), _jsxs("div", { className: "text-xs text-slate-500 mt-1", children: ["FIID ", b.fiid ?? '—', " \u00B7 ", b.loginMethodType, " auth \u00B7 ", b.countryIso2 ?? '—'] })] }, b.recId)))] }), _jsxs("div", { className: "space-y-3 border border-slate-200 rounded-md p-4", children: [_jsx("h2", { className: "text-sm font-medium text-slate-700", children: "Create new bank" }), _jsxs("div", { className: "grid grid-cols-2 gap-3 text-sm", children: [_jsx(Field, { label: "Code", value: draft.code, onChange: v => setDraft({ ...draft, code: v }) }), _jsx(Field, { label: "Name", value: draft.name, onChange: v => setDraft({ ...draft, name: v }) }), _jsx(Field, { label: "FIID", value: draft.fiid, onChange: v => setDraft({ ...draft, fiid: v }) }), _jsx(Field, { label: "Short", value: draft.shortCode, onChange: v => setDraft({ ...draft, shortCode: v }) }), _jsx(Field, { label: "Country ISO2", value: draft.countryIso2, onChange: v => setDraft({ ...draft, countryIso2: v }) }), _jsx(Field, { label: "SWIFT BIC", value: draft.swiftBic, onChange: v => setDraft({ ...draft, swiftBic: v }) }), _jsxs("label", { className: "col-span-2", children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Auth method" }), _jsxs("select", { value: draft.loginMethodType ?? 'DB', onChange: (e) => setDraft({ ...draft, loginMethodType: e.target.value }), className: "w-full input", children: [_jsx("option", { value: "DB", children: "DB (bcrypt)" }), _jsx("option", { value: "LDAP", children: "LDAP bind" }), _jsx("option", { value: "MSAD", children: "Active Directory" }), _jsx("option", { value: "OIDC", children: "OIDC (Phase 2)" })] })] }), (draft.loginMethodType === 'LDAP' || draft.loginMethodType === 'MSAD') && (_jsxs(_Fragment, { children: [_jsx(Field, { label: "LDAP IP", value: draft.ldapIp, onChange: v => setDraft({ ...draft, ldapIp: v }) }), _jsx(Field, { label: "LDAP Port", value: draft.ldapPort?.toString(), onChange: v => setDraft({ ...draft, ldapPort: Number(v) || undefined }) }), _jsx(Field, { label: "Base DN", value: draft.baseDn, onChange: v => setDraft({ ...draft, baseDn: v }) }), _jsx(Field, { label: "Search DN", value: draft.searchBaseDn, onChange: v => setDraft({ ...draft, searchBaseDn: v }) })] }))] }), _jsx("button", { onClick: () => createBank.mutate(draft), disabled: !draft.code || !draft.name || createBank.isPending, className: "rounded-md btn-primary disabled:opacity-50", children: createBank.isPending ? 'Creating…' : 'Create bank' })] })] }), selected && (_jsxs("div", { className: "space-y-2 border-t border-slate-200 pt-4", children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("h2", { className: "text-sm font-medium text-slate-700", children: ["Branches of ", banks.data?.find(b => b.recId === selected)?.name] }), _jsx("button", { onClick: () => setSelected(null), className: "btn-secondary text-xs py-1 px-2", children: "\u2715 Clear" })] }), branches.data?.length === 0 && _jsx("div", { className: "text-xs text-slate-500", children: "No branches." }), branches.data?.map((br) => (_jsxs("div", { className: "rounded-md border border-slate-200 p-3 text-sm", children: [_jsxs("div", { className: "flex justify-between items-baseline", children: [_jsx("div", { className: "font-medium", children: br.name }), _jsx("span", { className: "text-xs font-mono text-slate-500", children: br.code })] }), _jsxs("div", { className: "text-xs text-slate-500 mt-1", children: [br.city ?? '—', " / ", br.region ?? '—', " / ", br.countryIso2 ?? '—'] })] }, br.recId)))] }))] }));
}
function Field({ label, value, onChange }) {
    return (_jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: label }), _jsx("input", { value: value ?? '', onChange: (e) => onChange(e.target.value), className: "w-full input" })] }));
}
