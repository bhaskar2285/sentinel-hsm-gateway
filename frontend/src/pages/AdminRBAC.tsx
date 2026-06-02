import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Trash2 } from 'lucide-react';
import { api } from '../api/client';

interface Bank    { recId: number; code: string; name: string }
interface Role    { recId: number; roleName: string; description?: string }
interface Team    { recId: number; teamCode: string; teamName: string }
interface Staff   {
  recId: number; staffFname: string; staffLname: string; staffEmail?: string;
  staffLoginname: string; userStatusCode: string; samTeamId: number; employeeCode?: string;
}

type Tab = 'staff' | 'roles' | 'teams';

export default function AdminRBAC() {
  const [bankId, setBankId] = useState<number | null>(null);
  const [tab, setTab]       = useState<Tab>('staff');

  const banks = useQuery<Bank[]>({
    queryKey: ['admin', 'banks'],
    queryFn: async () => (await api.get('/admin/banks', { baseURL: '/api/v1' })).data,
  });

  return (
    <div className="space-y-6 max-w-6xl">
      <div>
        <h1 className="text-2xl font-semibold">SAM — Access Control</h1>
        <p className="text-xs text-slate-500 mt-1">
          ISC Security Access Management · staff, roles, teams per bank.
        </p>
      </div>

      <div>
        <div className="label">Bank</div>
        <select
          value={bankId ?? ''}
          onChange={(e) => { setBankId(e.target.value ? Number(e.target.value) : null); setTab('staff'); }}
          className="input max-w-xs"
        >
          <option value="">— select a bank —</option>
          {banks.data?.map(b => (
            <option key={b.recId} value={b.recId}>{b.name} ({b.code})</option>
          ))}
        </select>
      </div>

      {bankId && (
        <div className="space-y-4">
          <div className="flex gap-1 border-b border-slate-200">
            {(['staff', 'roles', 'teams'] as Tab[]).map(t => (
              <button key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-2 text-sm font-medium capitalize border-b-2 -mb-px transition-colors ${
                  tab === t
                    ? 'border-sky-600 text-sky-700'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}>
                {t}
              </button>
            ))}
          </div>

          {tab === 'staff'  && <StaffPanel  bankId={bankId} />}
          {tab === 'roles'  && <RolesPanel  bankId={bankId} />}
          {tab === 'teams'  && <TeamsPanel  bankId={bankId} />}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Staff tab                                                           */
/* ------------------------------------------------------------------ */
function StaffPanel({ bankId }: { bankId: number }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ staffFname: '', staffLname: '', staffEmail: '',
    staffLoginname: '', password: '', employeeCode: '', samTeamId: '' });
  const [resetId, setResetId] = useState<number | null>(null);
  const [newPwd,  setNewPwd]  = useState('');

  const staff = useQuery<Staff[]>({
    queryKey: ['admin', 'sam', bankId, 'staff'],
    queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/staff`, { baseURL: '/api/v1' })).data,
    enabled: !!bankId,
  });
  const teams = useQuery<Team[]>({
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
    onError: (e: any) => toast.error(e?.response?.data?.message ?? e.message ?? 'failed'),
  });

  const resetPwd = useMutation({
    mutationFn: async (id: number) =>
      (await api.post(`/admin/sam/staff/${id}/reset-password`, { password: newPwd }, { baseURL: '/api/v1' })).data,
    onSuccess: () => {
      toast.success('Password reset — user must change on next login');
      setResetId(null); setNewPwd('');
      qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'staff'] });
    },
    onError: (e: any) => toast.error(e?.message ?? 'failed'),
  });

  return (
    <div className="space-y-6">
      {/* list */}
      <div className="table-wrap">
        <table className="w-full text-sm">
          <thead className="table-head">
            <tr>
              <th className="text-left px-4 py-2.5">Name</th>
              <th className="text-left px-4 py-2.5">Login</th>
              <th className="text-left px-4 py-2.5">Status</th>
              <th className="text-left px-4 py-2.5">Team</th>
              <th className="text-left px-4 py-2.5">Actions</th>
            </tr>
          </thead>
          <tbody>
            {staff.isLoading && (
              <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500 text-sm">Loading…</td></tr>
            )}
            {staff.data?.map(s => (
              <tr key={s.recId} className="table-row">
                <td className="px-4 py-2.5">{s.staffFname} {s.staffLname}</td>
                <td className="px-4 py-2.5 font-mono text-xs">{s.staffLoginname}</td>
                <td className="px-4 py-2.5">
                  <span className={s.userStatusCode === 'ACTIVE' ? 'badge-ok' : 'badge-err'}>
                    {s.userStatusCode}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-500">
                  {teams.data?.find(t => t.recId === s.samTeamId)?.teamName ?? `#${s.samTeamId}`}
                </td>
                <td className="px-4 py-2.5">
                  <button onClick={() => { setResetId(s.recId); setNewPwd(''); }}
                          className="btn-secondary text-xs py-1 px-2">
                    Reset pwd
                  </button>
                </td>
              </tr>
            ))}
            {staff.data?.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500 text-sm">No staff in this bank.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* password reset inline */}
      {resetId != null && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 space-y-2">
          <div className="text-xs font-medium text-amber-800">
            Reset password for staff #{resetId}
          </div>
          <div className="flex gap-2">
            <input value={newPwd} onChange={e => setNewPwd(e.target.value)}
                   type="password" placeholder="New password" className="input max-w-xs" />
            <button onClick={() => resetPwd.mutate(resetId!)}
                    disabled={!newPwd || resetPwd.isPending}
                    className="btn-primary text-xs">Apply</button>
            <button onClick={() => setResetId(null)} className="btn-secondary text-xs">Cancel</button>
          </div>
        </div>
      )}

      {/* create form */}
      <div className="border border-slate-200 rounded-lg p-4 space-y-3">
        <div className="text-sm font-medium text-slate-700">Add staff member</div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <SF label="First name"   value={form.staffFname}     onChange={v => setForm({...form, staffFname: v})} />
          <SF label="Last name"    value={form.staffLname}     onChange={v => setForm({...form, staffLname: v})} />
          <SF label="Login name"   value={form.staffLoginname} onChange={v => setForm({...form, staffLoginname: v})} />
          <SF label="Email"        value={form.staffEmail}     onChange={v => setForm({...form, staffEmail: v})} />
          <SF label="Password"     value={form.password}       onChange={v => setForm({...form, password: v})} type="password" />
          <SF label="Employee code" value={form.employeeCode}  onChange={v => setForm({...form, employeeCode: v})} />
          <label className="col-span-2">
            <div className="text-xs text-slate-600 mb-1">Team</div>
            <select value={form.samTeamId} onChange={e => setForm({...form, samTeamId: e.target.value})}
                    className="input">
              <option value="">— pick a team —</option>
              {teams.data?.map(t => (
                <option key={t.recId} value={t.recId}>{t.teamName} ({t.teamCode})</option>
              ))}
            </select>
          </label>
        </div>
        <button onClick={() => create.mutate()}
                disabled={!form.staffFname || !form.staffLname || !form.staffLoginname || !form.samTeamId || create.isPending}
                className="btn-primary rounded-md disabled:opacity-50">
          {create.isPending ? 'Creating…' : 'Create staff'}
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Roles tab                                                           */
/* ------------------------------------------------------------------ */
function RolesPanel({ bankId }: { bankId: number }) {
  const qc = useQueryClient();
  const [roleName, setRoleName] = useState('');
  const [desc,     setDesc]     = useState('');

  const roles = useQuery<Role[]>({
    queryKey: ['admin', 'sam', bankId, 'roles'],
    queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/roles`, { baseURL: '/api/v1' })).data,
    enabled: !!bankId,
  });

  const create = useMutation({
    mutationFn: async () => (await api.post(`/admin/sam/banks/${bankId}/roles`,
      { roleName, description: desc }, { baseURL: '/api/v1' })).data,
    onSuccess: () => {
      toast.success('Role created');
      qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'roles'] });
      setRoleName(''); setDesc('');
    },
    onError: (e: any) => toast.error(e?.message ?? 'failed'),
  });

  const del = useMutation({
    mutationFn: async (id: number) => api.delete(`/admin/sam/roles/${id}`, { baseURL: '/api/v1' }),
    onSuccess: () => {
      toast.success('Role deactivated');
      qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'roles'] });
    },
    onError: (e: any) => toast.error(e?.message ?? 'failed'),
  });

  return (
    <div className="space-y-4">
      <div className="table-wrap">
        <table className="w-full text-sm">
          <thead className="table-head">
            <tr>
              <th className="text-left px-4 py-2.5">Role name</th>
              <th className="text-left px-4 py-2.5">Description</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {roles.isLoading && (
              <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">Loading…</td></tr>
            )}
            {roles.data?.map(r => (
              <tr key={r.recId} className="table-row">
                <td className="px-4 py-2.5 font-mono text-xs">{r.roleName}</td>
                <td className="px-4 py-2.5 text-slate-600 text-xs">{r.description ?? '—'}</td>
                <td className="px-4 py-2.5 text-right">
                  <button onClick={() => del.mutate(r.recId)} title="Deactivate"
                          className="btn-ghost text-rose-600 p-1">
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {roles.data?.length === 0 && (
              <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">No roles.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="border border-slate-200 rounded-lg p-4 space-y-3">
        <div className="text-sm font-medium text-slate-700">New role</div>
        <div className="grid grid-cols-2 gap-3">
          <SF label="Role name" value={roleName} onChange={setRoleName} />
          <SF label="Description" value={desc}   onChange={setDesc} />
        </div>
        <button onClick={() => create.mutate()}
                disabled={!roleName || create.isPending}
                className="btn-primary rounded-md disabled:opacity-50">
          {create.isPending ? 'Creating…' : 'Create role'}
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Teams tab                                                           */
/* ------------------------------------------------------------------ */
function TeamsPanel({ bankId }: { bankId: number }) {
  const qc = useQueryClient();
  const [teamCode, setCode] = useState('');
  const [teamName, setName] = useState('');
  const [bindTeam, setBindTeam] = useState('');
  const [bindRole, setBindRole] = useState('');

  const teams = useQuery<Team[]>({
    queryKey: ['admin', 'sam', bankId, 'teams'],
    queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/teams`, { baseURL: '/api/v1' })).data,
    enabled: !!bankId,
  });
  const roles = useQuery<Role[]>({
    queryKey: ['admin', 'sam', bankId, 'roles'],
    queryFn: async () => (await api.get(`/admin/sam/banks/${bankId}/roles`, { baseURL: '/api/v1' })).data,
    enabled: !!bankId,
  });

  const create = useMutation({
    mutationFn: async () => (await api.post(`/admin/sam/banks/${bankId}/teams`,
      { teamCode, teamName }, { baseURL: '/api/v1' })).data,
    onSuccess: () => {
      toast.success('Team created');
      qc.invalidateQueries({ queryKey: ['admin', 'sam', bankId, 'teams'] });
      setCode(''); setName('');
    },
    onError: (e: any) => toast.error(e?.message ?? 'failed'),
  });

  const bind = useMutation({
    mutationFn: async () =>
      (await api.post(`/admin/sam/teams/${bindTeam}/roles/${bindRole}`, {}, { baseURL: '/api/v1' })).data,
    onSuccess: () => { toast.success('Team–role bound'); setBindTeam(''); setBindRole(''); },
    onError: (e: any) => toast.error(e?.message ?? 'already bound or failed'),
  });

  return (
    <div className="space-y-4">
      <div className="table-wrap">
        <table className="w-full text-sm">
          <thead className="table-head">
            <tr>
              <th className="text-left px-4 py-2.5">Code</th>
              <th className="text-left px-4 py-2.5">Name</th>
            </tr>
          </thead>
          <tbody>
            {teams.isLoading && (
              <tr><td colSpan={2} className="px-4 py-6 text-center text-slate-500">Loading…</td></tr>
            )}
            {teams.data?.map(t => (
              <tr key={t.recId} className="table-row">
                <td className="px-4 py-2.5 font-mono text-xs">{t.teamCode}</td>
                <td className="px-4 py-2.5">{t.teamName}</td>
              </tr>
            ))}
            {teams.data?.length === 0 && (
              <tr><td colSpan={2} className="px-4 py-6 text-center text-slate-500">No teams.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="border border-slate-200 rounded-lg p-4 space-y-3">
          <div className="text-sm font-medium text-slate-700">New team</div>
          <SF label="Team code" value={teamCode} onChange={setCode} />
          <SF label="Team name" value={teamName} onChange={setName} />
          <button onClick={() => create.mutate()}
                  disabled={!teamCode || !teamName || create.isPending}
                  className="btn-primary rounded-md disabled:opacity-50">
            {create.isPending ? 'Creating…' : 'Create team'}
          </button>
        </div>

        <div className="border border-slate-200 rounded-lg p-4 space-y-3">
          <div className="text-sm font-medium text-slate-700">Bind team → role</div>
          <label>
            <div className="text-xs text-slate-600 mb-1">Team</div>
            <select value={bindTeam} onChange={e => setBindTeam(e.target.value)} className="input">
              <option value="">— pick —</option>
              {teams.data?.map(t => (
                <option key={t.recId} value={t.recId}>{t.teamName}</option>
              ))}
            </select>
          </label>
          <label>
            <div className="text-xs text-slate-600 mb-1">Role</div>
            <select value={bindRole} onChange={e => setBindRole(e.target.value)} className="input">
              <option value="">— pick —</option>
              {roles.data?.map(r => (
                <option key={r.recId} value={r.recId}>{r.roleName}</option>
              ))}
            </select>
          </label>
          <button onClick={() => bind.mutate()}
                  disabled={!bindTeam || !bindRole || bind.isPending}
                  className="btn-primary rounded-md disabled:opacity-50">
            {bind.isPending ? 'Binding…' : 'Bind'}
          </button>
        </div>
      </div>
    </div>
  );
}

function SF({ label, value, onChange, type = 'text' }: {
  label: string; value: string; onChange: (v: string) => void; type?: string;
}) {
  return (
    <label>
      <div className="text-xs text-slate-600 mb-1">{label}</div>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} className="w-full input" />
    </label>
  );
}
