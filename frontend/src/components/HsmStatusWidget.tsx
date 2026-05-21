import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

type Node = { id: number; vendor: string; host: string; port: number; enabled: boolean; health: string };

export default function HsmStatusWidget() {
  const { data } = useQuery<Node[]>({
    queryKey: ['hsms-widget'],
    queryFn: () => api.get('/hsms').then((r) => r.data),
    refetchInterval: 5000,
  });

  const nodes = (data ?? []).filter((n) => n.enabled);
  const up    = nodes.filter((n) => n.health === 'UP').length;
  const total = nodes.length;
  const allUp = total > 0 && up === total;
  const allDn = total > 0 && up === 0;

  const dot = allUp
    ? 'bg-sky-500 shadow-[0_0_8px] shadow-sky-500'
    : allDn
    ? 'bg-red-400 shadow-[0_0_8px] shadow-red-400'
    : 'bg-amber-400 shadow-[0_0_8px] shadow-amber-400';

  const label = total === 0
    ? 'No HSMs'
    : allUp ? 'All HSMs online'
    : allDn ? 'All HSMs offline'
    : `${up}/${total} HSMs online`;

  return (
    <div className="flex items-center gap-2 text-xs text-slate-600 border border-slate-200 rounded-md px-3 py-1.5 bg-white shadow-sm">
      <span className={`w-2 h-2 rounded-full ${dot}`} />
      <span>{label}</span>
    </div>
  );
}
