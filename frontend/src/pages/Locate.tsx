import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { keysApi, KeySummary } from '../api/keys';

export default function Locate() {
  const [label, setLabel] = useState('');
  const [keyType, setKeyType] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['keys', label, keyType],
    queryFn: () => keysApi.list({ label: label || undefined, keyType: keyType || undefined }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-2xl font-semibold">Locate Keys</h1>
        <Link to="/keys/new" className="text-sm text-sky-600 hover:text-sky-700">
          + New Key
        </Link>
      </div>

      <div className="flex gap-2">
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Label contains..."
          className="flex-1 rounded-md bg-slate-50 border border-slate-200 px-3 py-2 text-sm"
        />
        <select
          value={keyType}
          onChange={(e) => setKeyType(e.target.value)}
          className="rounded-md bg-slate-50 border border-slate-200 px-3 py-2 text-sm"
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
      {error ? <div className="text-red-700 text-sm">Error: {(error as Error).message}</div> : null}

      <div className="overflow-hidden rounded-lg border border-slate-200">
        <table className="w-full text-sm">
          <thead className="bg-slate-50/80 text-slate-600">
            <tr>
              <th className="text-left px-4 py-2">Label</th>
              <th className="text-left px-4 py-2">Type</th>
              <th className="text-left px-4 py-2">Algo</th>
              <th className="text-left px-4 py-2">Bits</th>
              <th className="text-left px-4 py-2">KCV</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Created</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((k: KeySummary) => (
              <tr key={k.keyId} className="border-t border-slate-200 hover:bg-white shadow-sm">
                <td className="px-4 py-2">
                  <Link to={`/keys/${k.keyId}`} className="text-sky-600 hover:underline">
                    {k.label}
                  </Link>
                </td>
                <td className="px-4 py-2">{k.keyType}</td>
                <td className="px-4 py-2">{k.algo}</td>
                <td className="px-4 py-2">{k.keyLengthBits}</td>
                <td className="px-4 py-2 font-mono text-xs">{k.kcv ?? '-'}</td>
                <td className="px-4 py-2">{k.status}</td>
                <td className="px-4 py-2 text-slate-500">{new Date(k.createdAt).toISOString().slice(0, 16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
