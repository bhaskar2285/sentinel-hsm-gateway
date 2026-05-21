import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { PlusCircle, Search } from 'lucide-react';
import { keysApi, KeySummary } from '../api/keys';

export default function Locate() {
  const [label, setLabel] = useState('');
  const [keyType, setKeyType] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['keys', label, keyType],
    queryFn: () => keysApi.list({ label: label || undefined, keyType: keyType || undefined }),
  });

  return (
    <div className="space-y-6 max-w-7xl">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Key Vault</h1>
          <p className="text-sm text-slate-500 mt-1">All keys held under LMK. {data?.length ?? 0} entries.</p>
        </div>
        <Link to="/keys/new" className="btn-primary">
          <PlusCircle size={14} /> New RSA Key
        </Link>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Search by label…"
            className="input pl-9"
          />
        </div>
        <select
          value={keyType}
          onChange={(e) => setKeyType(e.target.value)}
          className="select max-w-[180px]"
        >
          <option value="">All types</option>
          <option>RSA</option>
          <option>AES</option>
          <option>3DES</option>
          <option>ZMK</option>
          <option>ZPK</option>
          <option>TMK</option>
          <option>TPK</option>
          <option>KBPK</option>
          <option>BDK</option>
        </select>
      </div>

      {isLoading && <div className="text-slate-500 text-sm">Loading…</div>}
      {error ? <div className="badge-err">Error: {(error as Error).message}</div> : null}

      <div className="table-wrap">
        <table className="w-full text-sm">
          <thead className="table-head">
            <tr>
              <th className="text-left px-4 py-2.5">Label</th>
              <th className="text-left px-4 py-2.5">Type</th>
              <th className="text-left px-4 py-2.5">Algo</th>
              <th className="text-left px-4 py-2.5">Bits</th>
              <th className="text-left px-4 py-2.5">KCV</th>
              <th className="text-left px-4 py-2.5">Bank</th>
              <th className="text-left px-4 py-2.5">Status</th>
              <th className="text-left px-4 py-2.5">Created</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((k: KeySummary) => (
              <tr key={k.keyId} className="table-row">
                <td className="px-4 py-2.5">
                  <Link to={`/keys/${k.keyId}`} className="text-sky-600 hover:text-sky-700 font-medium">
                    {k.label}
                  </Link>
                </td>
                <td className="px-4 py-2.5"><span className="badge-mute">{k.keyType}</span></td>
                <td className="px-4 py-2.5 text-slate-600">{k.algo}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-600">{k.keyLengthBits}</td>
                <td className="px-4 py-2.5"><span className="chip-mono">{k.kcv ?? '—'}</span></td>
                <td className="px-4 py-2.5">
                  {k.bankRecId ? <span className="badge-info">#{k.bankRecId}</span> : <span className="text-slate-400 text-xs">—</span>}
                </td>
                <td className="px-4 py-2.5">
                  <span className={k.status === 'ACTIVE' ? 'badge-ok' : 'badge-mute'}>{k.status}</span>
                </td>
                <td className="px-4 py-2.5 text-slate-500 font-mono text-xs">
                  {new Date(k.createdAt).toISOString().slice(0, 16).replace('T', ' ')}
                </td>
              </tr>
            ))}
            {data?.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-10 text-center text-slate-500 text-sm">
                No keys match. Try a different filter or generate one.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
