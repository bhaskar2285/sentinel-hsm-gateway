import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { api } from '../api/client';

interface Bank {
  recId: number;
  code: string;
  name: string;
  fiid?: string;
  shortCode?: string;
  isDefault?: string;
  loginMethodType: string;
  permissionMethodType: string;
  ldapIp?: string;
  ldapPort?: number;
  baseDn?: string;
  searchBaseDn?: string;
  countryIso2?: string;
  swiftBic?: string;
  recordStatus: string;
}

interface Branch {
  recId: number;
  bankRecId: number;
  code: string;
  name: string;
  city?: string;
  region?: string;
  countryIso2?: string;
  recordStatus: string;
}

export default function AdminBanks() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<number | null>(null);
  const [draft, setDraft] = useState<Partial<Bank>>({ loginMethodType: 'DB', permissionMethodType: 'DB' });

  const banks = useQuery<Bank[]>({
    queryKey: ['admin', 'banks'],
    queryFn: async () => (await api.get('/admin/banks', { baseURL: '/api/v1' })).data,
  });

  const branches = useQuery<Branch[]>({
    queryKey: ['admin', 'banks', selected, 'branches'],
    queryFn: async () => (await api.get(`/admin/banks/${selected}/branches`, { baseURL: '/api/v1' })).data,
    enabled: !!selected,
  });

  const createBank = useMutation({
    mutationFn: async (b: Partial<Bank>) => (await api.post('/admin/banks', b, { baseURL: '/api/v1' })).data,
    onSuccess: () => {
      toast.success('Bank created');
      qc.invalidateQueries({ queryKey: ['admin', 'banks'] });
      setDraft({ loginMethodType: 'DB', permissionMethodType: 'DB' });
    },
    onError: (e: any) => toast.error(e?.message ?? 'create failed'),
  });

  return (
    <div className="space-y-6 max-w-6xl">
      <h1 className="text-2xl font-semibold">Banks & Branches</h1>
      <p className="text-xs text-slate-500">ISC FIID master. Per-bank auth method (DB / LDAP / MSAD / OIDC).</p>

      <div className="grid grid-cols-2 gap-6">
        {/* Existing banks */}
        <div className="space-y-2">
          <h2 className="text-sm font-medium text-slate-700">Existing</h2>
          {banks.isLoading && <div className="text-slate-500 text-sm">Loading…</div>}
          {banks.data?.map((b) => (
            <div key={b.recId}
                 onClick={() => setSelected(b.recId)}
                 className={`rounded-md border p-3 cursor-pointer text-sm ${
                   selected === b.recId ? 'border-sky-600 bg-sky-50' : 'border-slate-200 hover:border-slate-300'
                 }`}>
              <div className="flex justify-between items-baseline">
                <div className="font-medium">{b.name}</div>
                <span className="text-xs font-mono text-slate-500">{b.code}</span>
              </div>
              <div className="text-xs text-slate-500 mt-1">
                FIID {b.fiid ?? '—'} · {b.loginMethodType} auth · {b.countryIso2 ?? '—'}
              </div>
            </div>
          ))}
        </div>

        {/* Create bank */}
        <div className="space-y-3 border border-slate-200 rounded-md p-4">
          <h2 className="text-sm font-medium text-slate-700">Create new bank</h2>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Field label="Code" value={draft.code}    onChange={v => setDraft({ ...draft, code: v })} />
            <Field label="Name" value={draft.name}    onChange={v => setDraft({ ...draft, name: v })} />
            <Field label="FIID" value={draft.fiid}    onChange={v => setDraft({ ...draft, fiid: v })} />
            <Field label="Short" value={draft.shortCode} onChange={v => setDraft({ ...draft, shortCode: v })} />
            <Field label="Country ISO2" value={draft.countryIso2} onChange={v => setDraft({ ...draft, countryIso2: v })} />
            <Field label="SWIFT BIC"    value={draft.swiftBic}    onChange={v => setDraft({ ...draft, swiftBic: v })} />
            <label className="col-span-2">
              <div className="text-xs text-slate-600 mb-1">Auth method</div>
              <select value={draft.loginMethodType ?? 'DB'}
                      onChange={(e) => setDraft({ ...draft, loginMethodType: e.target.value })}
                      className="w-full input">
                <option value="DB">DB (bcrypt)</option>
                <option value="LDAP">LDAP bind</option>
                <option value="MSAD">Active Directory</option>
                <option value="OIDC">OIDC (Phase 2)</option>
              </select>
            </label>
            {(draft.loginMethodType === 'LDAP' || draft.loginMethodType === 'MSAD') && (
              <>
                <Field label="LDAP IP"   value={draft.ldapIp}       onChange={v => setDraft({ ...draft, ldapIp: v })} />
                <Field label="LDAP Port" value={draft.ldapPort?.toString()} onChange={v => setDraft({ ...draft, ldapPort: Number(v) || undefined })} />
                <Field label="Base DN"   value={draft.baseDn}       onChange={v => setDraft({ ...draft, baseDn: v })} />
                <Field label="Search DN" value={draft.searchBaseDn} onChange={v => setDraft({ ...draft, searchBaseDn: v })} />
              </>
            )}
          </div>
          <button onClick={() => createBank.mutate(draft)}
                  disabled={!draft.code || !draft.name || createBank.isPending}
                  className="rounded-md btn-primary disabled:opacity-50">
            {createBank.isPending ? 'Creating…' : 'Create bank'}
          </button>
        </div>
      </div>

      {/* Branches of selected bank */}
      {selected && (
        <div className="space-y-2 border-t border-slate-200 pt-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium text-slate-700">
              Branches of {banks.data?.find(b => b.recId === selected)?.name}
            </h2>
            <button onClick={() => setSelected(null)} className="btn-secondary text-xs py-1 px-2">
              ✕ Clear
            </button>
          </div>
          {branches.data?.length === 0 && <div className="text-xs text-slate-500">No branches.</div>}
          {branches.data?.map((br) => (
            <div key={br.recId} className="rounded-md border border-slate-200 p-3 text-sm">
              <div className="flex justify-between items-baseline">
                <div className="font-medium">{br.name}</div>
                <span className="text-xs font-mono text-slate-500">{br.code}</span>
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {br.city ?? '—'} / {br.region ?? '—'} / {br.countryIso2 ?? '—'}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, value, onChange }: { label: string; value?: string; onChange: (v: string) => void }) {
  return (
    <label>
      <div className="text-xs text-slate-600 mb-1">{label}</div>
      <input value={value ?? ''} onChange={(e) => onChange(e.target.value)}
             className="w-full input"/>
    </label>
  );
}
