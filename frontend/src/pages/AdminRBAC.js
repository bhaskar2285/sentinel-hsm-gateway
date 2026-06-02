import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Trash2 } from 'lucide-react';
import { api } from '../api/client';
export default function AdminRBAC() {
    const [bankId, setBankId] = useState(null);
    const [tab, setTab] = useState('staff');
    const banks = useQuery({
        queryKey: ['admin', 'banks'],
        queryFn: async () => (await api.get('/admin/banks', { baseURL: '/api/v1' })).data,
    });
    return (_jsxs("div", { className: "space-y-6 max-w-6xl", children: [_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold", children: "SAM \u2014 Access Control" }), _jsx("p", { className: "text-xs text-slate-500 mt-1", children: "ISC Security Access Management \u00B7 staff, roles, teams per bank." })] }), _jsxs("div", { children: [_jsx("div", { className: "label", children: "Bank" }), _jsxs("select", { value: bankId ?? '', onChange: (e) => { setBankId(e.target.value ? Number(e.target.value) : null); setTab('staff'); }, className: "input max-w-xs", children: [_jsx("option", { value: "", children: "\u2014 select a bank \u2014" }), banks.data?.map(b => (_jsxs("option", { value: b.recId, children: [b.name, " (", b.code, ")"] }, b.recId)))] })] }), bankId && (_jsxs("div", { className: "space-y-4", children: [_jsx("div", { className: "flex gap-1 border-b border-slate-200", children: ['staff', 'roles', 'teams'].map(t => (_jsx("button", { onClick: () => setTab(t), className: `px-4 py-2 text-sm font-medium capitalize border-b-2 -mb-px transition-colors ${tab === t
                                ? 'border-sky-600 text-sky-700'
                                : 'border-transparent text-slate-500 hover:text-slate-800'}`, children: t }, t))) }), tab === 'staff' && _jsx(StaffPanel, { bankId: bankId }), tab === 'roles' && _jsx(RolesPanel, { bankId: bankId }), tab === 'teams' && _jsx(TeamsPanel, { bankId: bankId })] }))] }));
}
/* ------------------------------------------------------------------ */
/* Staff tab                                                           */
/* ------------------------------------------------------------------ */
function StaffPanel({ bankId }) {
    const qc = useQueryClient();
    const [form, setForm] = useState({ staffFname: '', staffLname: '', staffEmail: '',
        staffLoginname: '', password: '', employeeCode: '', samTeamId: '' });
    const [resetId, setResetId] = useState(null);
    const [newPwd, setNewPwd] = useState('');
    const staff = useQuery({
        queryKey: ['admin', 'sam', bankId, 'staff'],
        queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/staff`, { baseURL: '/api/v1' })).data,
        enabled: !!bankId,
    });
    const teams = useQuery({
        queryKey: ['admin', 'sam', bankId, 'teams'],
        queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/teams`, { baseURL: '/api/v1' })).data,
        enabled: !!bankId,
    });
    const create = useMutation({
        mutationFn: async () => (await api.post(`/admin/sam/banks/${bankId}/staff`, {
            ...form, samTeamId: form.samTeamId ? Number(form.samTeamId) : undefined,
        }, { baseURL: '/api/v1' })).data,
        onSuccess: () => {
            toast.success('Staff created');
            qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'staff'] });
            setForm({ staffFname: '', staffLname: '', staffEmail: '', staffLoginname: '',
                password: '', employeeCode: '', samTeamId: '' });
        },
        onError: (e) => toast.error(e?.response?.data?.message ?? e.message ?? 'failed'),
    });
    const resetPwd = useMutation({
        mutationFn: async (id) => (await api.post(`/admin/sam/staff/${id}/reset-password`, { password: newPwd }, { baseURL: '/api/v1' })).data,
        onSuccess: () => {
            toast.success('Password reset — user must change on next login');
            setResetId(null);
            setNewPwd('');
            qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'staff'] });
        },
        onError: (e) => toast.error(e?.message ?? 'failed'),
    });
    return (_jsxs("div", { className: "space-y-6", children: [_jsx("div", { className: "table-wrap", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "table-head", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left px-4 py-2.5", children: "Name" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Login" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Status" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Team" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Actions" })] }) }), _jsxs("tbody", { children: [staff.isLoading && (_jsx("tr", { children: _jsx("td", { colSpan: 5, className: "px-4 py-6 text-center text-slate-500 text-sm", children: "Loading\u2026" }) })), staff.data?.map(s => (_jsxs("tr", { className: "table-row", children: [_jsxs("td", { className: "px-4 py-2.5", children: [s.staffFname, " ", s.staffLname] }), _jsx("td", { className: "px-4 py-2.5 font-mono text-xs", children: s.staffLoginname }), _jsx("td", { className: "px-4 py-2.5", children: _jsx("span", { className: s.userStatusCode === 'ACTIVE' ? 'badge-ok' : 'badge-err', children: s.userStatusCode }) }), _jsx("td", { className: "px-4 py-2.5 text-xs text-slate-500", children: teams.data?.find(t => t.recId === s.samTeamId)?.teamName ?? `#${s.samTeamId}` }), _jsx("td", { className: "px-4 py-2.5", children: _jsx("button", { onClick: () => { setResetId(s.recId); setNewPwd(''); }, className: "btn-secondary text-xs py-1 px-2", children: "Reset pwd" }) })] }, s.recId))), staff.data?.length === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 5, className: "px-4 py-6 text-center text-slate-500 text-sm", children: "No staff in this bank." }) }))] })] }) }), resetId != null && (_jsxs("div", { className: "rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 space-y-2", children: [_jsxs("div", { className: "text-xs font-medium text-amber-800", children: ["Reset password for staff #", resetId] }), _jsxs("div", { className: "flex gap-2", children: [_jsx("input", { value: newPwd, onChange: e => setNewPwd(e.target.value), type: "password", placeholder: "New password", className: "input max-w-xs" }), _jsx("button", { onClick: () => resetPwd.mutate(resetId), disabled: !newPwd || resetPwd.isPending, className: "btn-primary text-xs", children: "Apply" }), _jsx("button", { onClick: () => setResetId(null), className: "btn-secondary text-xs", children: "Cancel" })] })] })), _jsxs("div", { className: "border border-slate-200 rounded-lg p-4 space-y-3", children: [_jsx("div", { className: "text-sm font-medium text-slate-700", children: "Add staff member" }), _jsxs("div", { className: "grid grid-cols-2 gap-3 text-sm", children: [_jsx(SF, { label: "First name", value: form.staffFname, onChange: v => setForm({ ...form, staffFname: v }) }), _jsx(SF, { label: "Last name", value: form.staffLname, onChange: v => setForm({ ...form, staffLname: v }) }), _jsx(SF, { label: "Login name", value: form.staffLoginname, onChange: v => setForm({ ...form, staffLoginname: v }) }), _jsx(SF, { label: "Email", value: form.staffEmail, onChange: v => setForm({ ...form, staffEmail: v }) }), _jsx(SF, { label: "Password", value: form.password, onChange: v => setForm({ ...form, password: v }), type: "password" }), _jsx(SF, { label: "Employee code", value: form.employeeCode, onChange: v => setForm({ ...form, employeeCode: v }) }), _jsxs("label", { className: "col-span-2", children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Team" }), _jsxs("select", { value: form.samTeamId, onChange: e => setForm({ ...form, samTeamId: e.target.value }), className: "input", children: [_jsx("option", { value: "", children: "\u2014 pick a team \u2014" }), teams.data?.map(t => (_jsxs("option", { value: t.recId, children: [t.teamName, " (", t.teamCode, ")"] }, t.recId)))] })] })] }), _jsx("button", { onClick: () => create.mutate(), disabled: !form.staffFname || !form.staffLname || !form.staffLoginname || !form.samTeamId || create.isPending, className: "btn-primary rounded-md disabled:opacity-50", children: create.isPending ? 'Creating…' : 'Create staff' })] })] }));
}
/* ------------------------------------------------------------------ */
/* Roles tab                                                           */
/* ------------------------------------------------------------------ */
function RolesPanel({ bankId }) {
    const qc = useQueryClient();
    const [roleName, setRoleName] = useState('');
    const [desc, setDesc] = useState('');
    const roles = useQuery({
        queryKey: ['admin', 'sam', bankId, 'roles'],
        queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/roles`, { baseURL: '/api/v1' })).data,
        enabled: !!bankId,
    });
    const create = useMutation({
        mutationFn: async () => (await api.post(`/admin/sam/banks/${bankId}/roles`, { roleName, description: desc }, { baseURL: '/api/v1' })).data,
        onSuccess: () => {
            toast.success('Role created');
            qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'roles'] });
            setRoleName('');
            setDesc('');
        },
        onError: (e) => toast.error(e?.message ?? 'failed'),
    });
    const del = useMutation({
        mutationFn: async (id) => api.delete(`/admin/sam/roles/${id}`, { baseURL: '/api/v1' }),
        onSuccess: () => {
            toast.success('Role deactivated');
            qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'roles'] });
        },
        onError: (e) => toast.error(e?.message ?? 'failed'),
    });
    return (_jsxs("div", { className: "space-y-4", children: [_jsx("div", { className: "table-wrap", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "table-head", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left px-4 py-2.5", children: "Role name" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Description" }), _jsx("th", { className: "px-4 py-2.5" })] }) }), _jsxs("tbody", { children: [roles.isLoading && (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "px-4 py-6 text-center text-slate-500", children: "Loading\u2026" }) })), roles.data?.map(r => (_jsxs("tr", { className: "table-row", children: [_jsx("td", { className: "px-4 py-2.5 font-mono text-xs", children: r.roleName }), _jsx("td", { className: "px-4 py-2.5 text-slate-600 text-xs", children: r.description ?? '—' }), _jsx("td", { className: "px-4 py-2.5 text-right", children: _jsx("button", { onClick: () => del.mutate(r.recId), title: "Deactivate", className: "btn-ghost text-rose-600 p-1", children: _jsx(Trash2, { size: 14 }) }) })] }, r.recId))), roles.data?.length === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "px-4 py-6 text-center text-slate-500", children: "No roles." }) }))] })] }) }), _jsxs("div", { className: "border border-slate-200 rounded-lg p-4 space-y-3", children: [_jsx("div", { className: "text-sm font-medium text-slate-700", children: "New role" }), _jsxs("div", { className: "grid grid-cols-2 gap-3", children: [_jsx(SF, { label: "Role name", value: roleName, onChange: setRoleName }), _jsx(SF, { label: "Description", value: desc, onChange: setDesc })] }), _jsx("button", { onClick: () => create.mutate(), disabled: !roleName || create.isPending, className: "btn-primary rounded-md disabled:opacity-50", children: create.isPending ? 'Creating…' : 'Create role' })] })] }));
}
/* ------------------------------------------------------------------ */
/* Teams tab                                                           */
/* ------------------------------------------------------------------ */
function TeamsPanel({ bankId }) {
    const qc = useQueryClient();
    const [teamCode, setCode] = useState('');
    const [teamName, setName] = useState('');
    const [bindTeam, setBindTeam] = useState('');
    const [bindRole, setBindRole] = useState('');
    const teams = useQuery({
        queryKey: ['admin', 'sam', bankId, 'teams'],
        queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/teams`, { baseURL: '/api/v1' })).data,
        enabled: !!bankId,
    });
    const roles = useQuery({
        queryKey: ['admin', 'sam', bankId, 'roles'],
        queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/roles`, { baseURL: '/api/v1' })).data,
        enabled: !!bankId,
    });
    const create = useMutation({
        mutationFn: async () => (await api.post(`/admin/sam/banks/${bankId}/teams`, { teamCode, teamName }, { baseURL: '/api/v1' })).data,
        onSuccess: () => {
            toast.success('Team created');
            qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'teams'] });
            setCode('');
            setName('');
        },
        onError: (e) => toast.error(e?.message ?? 'failed'),
    });
    const bind = useMutation({
        mutationFn: async () => (await api.post(`/admin/sam/teams/${bindTeam}/roles/${bindRole}`, {}, { baseURL: '/api/v1' })).data,
        onSuccess: () => { toast.success('Team–role bound'); setBindTeam(''); setBindRole(''); },
        onError: (e) => toast.error(e?.message ?? 'already bound or failed'),
    });
    return (_jsxs("div", { className: "space-y-4", children: [_jsx("div", { className: "table-wrap", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "table-head", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left px-4 py-2.5", children: "Code" }), _jsx("th", { className: "text-left px-4 py-2.5", children: "Name" })] }) }), _jsxs("tbody", { children: [teams.isLoading && (_jsx("tr", { children: _jsx("td", { colSpan: 2, className: "px-4 py-6 text-center text-slate-500", children: "Loading\u2026" }) })), teams.data?.map(t => (_jsxs("tr", { className: "table-row", children: [_jsx("td", { className: "px-4 py-2.5 font-mono text-xs", children: t.teamCode }), _jsx("td", { className: "px-4 py-2.5", children: t.teamName })] }, t.recId))), teams.data?.length === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 2, className: "px-4 py-6 text-center text-slate-500", children: "No teams." }) }))] })] }) }), _jsxs("div", { className: "grid grid-cols-2 gap-4", children: [_jsxs("div", { className: "border border-slate-200 rounded-lg p-4 space-y-3", children: [_jsx("div", { className: "text-sm font-medium text-slate-700", children: "New team" }), _jsx(SF, { label: "Team code", value: teamCode, onChange: setCode }), _jsx(SF, { label: "Team name", value: teamName, onChange: setName }), _jsx("button", { onClick: () => create.mutate(), disabled: !teamCode || !teamName || create.isPending, className: "btn-primary rounded-md disabled:opacity-50", children: create.isPending ? 'Creating…' : 'Create team' })] }), _jsxs("div", { className: "border border-slate-200 rounded-lg p-4 space-y-3", children: [_jsx("div", { className: "text-sm font-medium text-slate-700", children: "Bind team \u2192 role" }), _jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Team" }), _jsxs("select", { value: bindTeam, onChange: e => setBindTeam(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 pick \u2014" }), teams.data?.map(t => (_jsx("option", { value: t.recId, children: t.teamName }, t.recId)))] })] }), _jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Role" }), _jsxs("select", { value: bindRole, onChange: e => setBindRole(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 pick \u2014" }), roles.data?.map(r => (_jsx("option", { value: r.recId, children: r.roleName }, r.recId)))] })] }), _jsx("button", { onClick: () => bind.mutate(), disabled: !bindTeam || !bindRole || bind.isPending, className: "btn-primary rounded-md disabled:opacity-50", children: bind.isPending ? 'Binding…' : 'Bind' })] })] })] }));
}
function SF({ label, value, onChange, type = 'text' }) {
    return (_jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: label }), _jsx("input", { type: type, value: value, onChange: e => onChange(e.target.value), className: "w-full input" })] }));
}
