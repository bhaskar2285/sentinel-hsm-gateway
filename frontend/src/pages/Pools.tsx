import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

type Pool = {
  id: number;
  vendor: string;
  name: string;
  lbStrategy: string;
  enabled: boolean;
};

type Node = {
  id: number;
  poolId: number;
  vendor: string;
  host: string;
  port: number;
  weight: number;
  direction: string;
  enabled: boolean;
  health: 'UP' | 'DOWN' | 'UNKNOWN' | 'DRAINING';
  lastSeen: string | null;
};

export default function Pools() {
  const pools = useQuery<Pool[]>({
    queryKey: ['pools'],
    queryFn: () => api.get('/pools').then((r) => r.data),
    refetchInterval: 5000,
  });
  const hsms = useQuery<Node[]>({
    queryKey: ['hsms'],
    queryFn: () => api.get('/hsms').then((r) => r.data),
    refetchInterval: 5000,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">HSM Pools</h1>

      <section>
        <h2 className="text-lg mb-3 text-slate-700">Pools</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {(pools.data ?? []).map((p) => {
            const poolNodes = (hsms.data ?? []).filter((n) => n.poolId === p.id);
            const upCount = poolNodes.filter((n) => n.health === 'UP').length;
            return (
              <div key={p.id} className="rounded-lg border border-slate-200 bg-white shadow-sm p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium">{p.name}</div>
                    <div className="text-xs text-slate-500">
                      {p.vendor} · {p.lbStrategy}
                    </div>
                  </div>
                  <span
                    className={`text-xs px-2 py-1 rounded font-mono ${
                      upCount > 0
                        ? 'bg-sky-500/15 text-sky-700'
                        : 'bg-red-500/15 text-red-700'
                    }`}
                  >
                    {upCount}/{poolNodes.length} UP
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h2 className="text-lg mb-3 text-slate-700">Nodes</h2>
        <div className="overflow-hidden rounded-lg border border-slate-200">
          <table className="w-full text-sm">
            <thead className="bg-slate-50/80 text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-left px-4 py-2">Vendor</th>
                <th className="text-left px-4 py-2">Host</th>
                <th className="text-left px-4 py-2">Port</th>
                <th className="text-left px-4 py-2">Dir</th>
                <th className="text-left px-4 py-2">Weight</th>
                <th className="text-left px-4 py-2">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {(hsms.data ?? []).map((n) => (
                <tr key={n.id} className="border-t border-slate-200 hover:bg-white shadow-sm">
                  <td className="px-4 py-2"><StatusBadge health={n.health} enabled={n.enabled} /></td>
                  <td className="px-4 py-2 font-mono text-xs">{n.vendor}</td>
                  <td className="px-4 py-2 font-mono text-xs">{n.host}</td>
                  <td className="px-4 py-2 font-mono text-xs">{n.port}</td>
                  <td className="px-4 py-2">{n.direction}</td>
                  <td className="px-4 py-2">{n.weight}</td>
                  <td className="px-4 py-2 text-slate-500 text-xs">
                    {n.lastSeen ? new Date(n.lastSeen).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function StatusBadge({ health, enabled }: { health: string; enabled: boolean }) {
  if (!enabled) {
    return (
      <span className="inline-flex items-center gap-2 text-xs">
        <span className="w-2 h-2 rounded-full bg-slate-400" />
        DISABLED
      </span>
    );
  }
  const map: Record<string, { dot: string; text: string; label: string }> = {
    UP:       { dot: 'bg-sky-500 shadow-[0_0_6px] shadow-sky-500', text: 'text-sky-700', label: 'ONLINE' },
    DOWN:     { dot: 'bg-red-400 shadow-[0_0_6px] shadow-red-400',         text: 'text-red-700',     label: 'OFFLINE' },
    DRAINING: { dot: 'bg-amber-400',                                       text: 'text-amber-300',   label: 'DRAINING' },
    UNKNOWN:  { dot: 'bg-slate-400 animate-pulse',                          text: 'text-slate-600',    label: 'PROBING' },
  };
  const s = map[health] ?? map.UNKNOWN;
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-medium ${s.text}`}>
      <span className={`w-2 h-2 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}
