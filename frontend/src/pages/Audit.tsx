import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface AuditRow {
  id: number;
  ts: string;
  userId: string;
  op: string;
  vendor: string;
  hsmNodeId: number | null;
  latencyMs: number | null;
  status: string;
  errCode: string;
  errText: string;
  requestHash: string;
  responseHash: string;
  traceId: string;
}

interface Page<T> { content: T[]; totalElements: number; number: number; size: number; }

export default function Audit() {
  const [op, setOp]         = useState('');
  const [userId, setUserId] = useState('');
  const [status, setStatus] = useState('');
  const [vendor, setVendor] = useState('');
  const [page, setPage]     = useState(0);
  const size = 25;

  const { data, isLoading, refetch } = useQuery<Page<AuditRow>>({
    queryKey: ['audit', op, userId, status, vendor, page],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, size };
      if (op)     params.op = op;
      if (userId) params.userId = userId;
      if (status) params.status = status;
      if (vendor) params.vendor = vendor;
      const r = await api.get('/audit', { params, baseURL: '/api/v1' });
      return r.data;
    },
  });

  return (
    <div className="space-y-4 max-w-6xl">
      <h1 className="text-2xl font-semibold">Audit Trail</h1>
      <p className="text-xs text-slate-500">SHA-256 request/response fingerprints. Raw bytes never persisted.</p>

      <div className="grid grid-cols-4 gap-3 text-sm">
        <input value={op}     onChange={(e) => setOp(e.target.value)}     placeholder="op (RSA_KEY_GEN…)"
               className="rounded-md bg-slate-50 border border-slate-200 px-3 py-2"/>
        <input value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="userId"
               className="rounded-md bg-slate-50 border border-slate-200 px-3 py-2"/>
        <select value={status} onChange={(e) => setStatus(e.target.value)}
               className="rounded-md bg-slate-50 border border-slate-200 px-3 py-2">
          <option value="">— status —</option>
          <option value="OK">OK</option>
          <option value="ERROR">ERROR</option>
          <option value="TIMEOUT">TIMEOUT</option>
        </select>
        <select value={vendor} onChange={(e) => setVendor(e.target.value)}
               className="rounded-md bg-slate-50 border border-slate-200 px-3 py-2">
          <option value="">— vendor —</option>
          <option value="THALES">THALES</option>
          <option value="UTIMACO">UTIMACO</option>
        </select>
      </div>

      <button onClick={() => { setPage(0); refetch(); }}
              className="rounded-md bg-sky-600 hover:bg-sky-500 px-4 py-2 text-sm">
        Search
      </button>

      {isLoading && <div className="text-slate-500">Loading…</div>}
      {data && (
        <>
          <div className="text-xs text-slate-500">{data.totalElements} rows</div>
          <div className="overflow-x-auto border border-slate-200 rounded-md">
            <table className="w-full text-xs">
              <thead className="bg-slate-50">
                <tr className="text-left text-slate-600">
                  <th className="px-3 py-2">Timestamp</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Op</th>
                  <th className="px-3 py-2">Vendor</th>
                  <th className="px-3 py-2">Node</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Err</th>
                  <th className="px-3 py-2">Latency</th>
                  <th className="px-3 py-2">Req hash</th>
                  <th className="px-3 py-2">Resp hash</th>
                </tr>
              </thead>
              <tbody>
                {data.content.map((r) => (
                  <tr key={r.id} className="border-t border-slate-200">
                    <td className="px-3 py-1.5 font-mono">{r.ts}</td>
                    <td className="px-3 py-1.5">{r.userId}</td>
                    <td className="px-3 py-1.5">{r.op}</td>
                    <td className="px-3 py-1.5">{r.vendor}</td>
                    <td className="px-3 py-1.5">{r.hsmNodeId}</td>
                    <td className={`px-3 py-1.5 ${r.status === 'OK' ? 'text-sky-600' : 'text-red-700'}`}>{r.status}</td>
                    <td className="px-3 py-1.5">{r.errCode}</td>
                    <td className="px-3 py-1.5">{r.latencyMs}ms</td>
                    <td className="px-3 py-1.5 font-mono text-slate-500" title={r.requestHash}>{r.requestHash?.slice(0, 12)}…</td>
                    <td className="px-3 py-1.5 font-mono text-slate-500" title={r.responseHash}>{r.responseHash?.slice(0, 12)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex gap-2 text-sm">
            <button disabled={page === 0} onClick={() => setPage(page - 1)}
                    className="rounded-md bg-slate-100 hover:bg-slate-200 disabled:opacity-40 px-3 py-1.5">← Prev</button>
            <span className="text-slate-500">page {page + 1}</span>
            <button disabled={(page + 1) * size >= (data?.totalElements ?? 0)} onClick={() => setPage(page + 1)}
                    className="rounded-md bg-slate-100 hover:bg-slate-200 disabled:opacity-40 px-3 py-1.5">Next →</button>
          </div>
        </>
      )}
    </div>
  );
}
