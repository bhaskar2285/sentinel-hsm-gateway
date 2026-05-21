import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { toast } from 'sonner';
import { keysApi, KeySummary } from '../api/keys';

const KBPK_TYPES = new Set(['ZMK', 'KBPK', 'TMK']);

export default function KeyDetail() {
  const { keyId } = useParams();
  const { data, isLoading } = useQuery({
    queryKey: ['key', keyId],
    queryFn: () => keysApi.get(keyId!),
    enabled: !!keyId,
  });
  const all = useQuery<KeySummary[]>({
    queryKey: ['keys'],
    queryFn: () => keysApi.list(),
  });

  const [format, setFormat] = useState<'TR31_B' | 'TR31_D' | 'X9_143' | 'RAW'>('TR31_D');
  const [kbpkKeyId, setKbpkKeyId] = useState<string>('');
  const [exported, setExported] = useState<string>('');
  const [busy, setBusy] = useState(false);

  const kbpkCandidates = (all.data ?? []).filter((k) => KBPK_TYPES.has(k.keyType) && k.keyId !== keyId);

  const doExport = async () => {
    if (!keyId) return;
    if (format !== 'RAW' && !kbpkKeyId) {
      toast.error('Pick a wrapping key (ZMK/KBPK/TMK)');
      return;
    }
    setBusy(true);
    try {
      const r = await keysApi.exportKey(keyId, { format, kbpkKeyId: kbpkKeyId || undefined });
      if (r.status === 'OK') {
        setExported(r.keyBlock);
        toast.success('Exported');
      } else {
        toast.error(`${r.errCode}: ${r.errText}`);
      }
    } finally {
      setBusy(false);
    }
  };

  if (isLoading) return <div className="text-slate-500">Loading…</div>;
  if (!data) return <div>Not found</div>;

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-2xl font-semibold">{data.label}</h1>
        <span className="text-xs px-2 py-1 rounded bg-slate-100">{data.status}</span>
      </div>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <Info k="Key ID" v={data.keyId} mono />
        <Info k="Type" v={data.keyType} />
        <Info k="Algorithm" v={data.algo} />
        <Info k="Bits" v={data.keyLengthBits} />
        <Info k="Usage" v={data.usage} />
        <Info k="KCV" v={data.kcv} mono />
        <Info k="Owner" v={data.ownerUserId} />
        <Info k="Vendor" v={data.vendorOrigin} />
        <Info k="Version" v={data.version} />
        <Info k="Created" v={data.createdAt} />
      </div>

      <div className="space-y-3 border-t border-slate-200 pt-4">
        <div>
          <h2 className="text-lg font-medium">
            Export <span className="text-xs font-mono text-slate-500">[A8/A9]</span>
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Wraps this key under a KBPK / ZMK so it can leave the HSM safely. Raw = LMK-encrypted blob (admin only).
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <label>
            <div className="text-xs text-slate-600 mb-1">Format</div>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as any)}
              className="w-full rounded-md bg-slate-50 border border-slate-200 px-3 py-2 text-sm"
            >
              <option value="TR31_B">TR-31 Format B (3DES KBPK)</option>
              <option value="TR31_D">TR-31 Format D (AES KBPK)</option>
              <option value="X9_143">ANSI X9.143</option>
              <option value="RAW">Raw (admin only)</option>
            </select>
          </label>
          <label>
            <div className="text-xs text-slate-600 mb-1">Wrapping key (ZMK / KBPK / TMK)</div>
            <select
              value={kbpkKeyId}
              onChange={(e) => setKbpkKeyId(e.target.value)}
              disabled={format === 'RAW'}
              className="w-full rounded-md bg-slate-50 border border-slate-200 px-3 py-2 text-sm disabled:opacity-40"
            >
              <option value="">{format === 'RAW' ? 'N/A (Raw mode)' : '— pick a key —'}</option>
              {kbpkCandidates.map((k) => (
                <option key={k.keyId} value={k.keyId}>
                  {k.label} ({k.keyType})
                </option>
              ))}
            </select>
          </label>
        </div>

        {kbpkCandidates.length === 0 && format !== 'RAW' && (
          <div className="text-xs text-amber-400">
            No ZMK/KBPK/TMK in vault. Import one first via "Import Key".
          </div>
        )}

        <button
          onClick={doExport}
          disabled={busy}
          className="rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-2 text-sm"
        >
          {busy ? 'Exporting…' : 'Export'}
        </button>

        {exported && (
          <div className="space-y-1">
            <div className="text-xs text-slate-600">Key block</div>
            <pre className="rounded-md border border-slate-200 bg-white p-3 text-xs font-mono overflow-auto break-all whitespace-pre-wrap">
              {exported}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function Info({ k, v, mono = false }: { k: string; v: any; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-slate-500">{k}</div>
      <div className={mono ? 'font-mono text-xs break-all' : ''}>{v ?? '-'}</div>
    </div>
  );
}
