import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { keysApi, type KeySummary } from '../api/keys';

const KEY_TYPES = [
  { code: '000', name: 'ZMK',  desc: 'Zone Master Key — wraps other keys for transport' },
  { code: '001', name: 'ZPK',  desc: 'Zone PIN Key — encrypts PIN blocks on the wire' },
  { code: '002', name: 'KBPK', desc: 'Key Block Protection Key — TR-31 wrap KEK' },
  { code: '008', name: 'TMK',  desc: 'Terminal Master Key — POS/ATM injection' },
  { code: '00A', name: 'DATA', desc: 'Generic data encryption key' },
];

const SCHEMES = [
  { code: 'U', name: 'U — 3DES double-length (128b)' },
  { code: 'T', name: 'T — 3DES triple-length (192b)' },
  { code: 'R', name: 'R — AES-128' },
  { code: 'S', name: 'S — AES-192' },
  { code: 'H', name: 'H — AES-256' },
];

export default function KeyCreateSym() {
  const nav = useNavigate();
  const [label, setLabel]       = useState('');
  const [keyType, setKeyType]   = useState('001');
  const [keyScheme, setScheme]  = useState('U');
  const [mode, setMode]         = useState('0');
  const [zmkKeyId, setZmkKeyId] = useState('');
  const [outScheme, setOut]     = useState('U');
  const [busy, setBusy]         = useState(false);

  const zmkList = useQuery<KeySummary[]>({
    queryKey: ['keys', 'zmk-list'],
    queryFn: () => keysApi.list({ keyType: 'ZMK' }),
    enabled: mode === '1',
  });

  const submit = async () => {
    if (!label.trim()) return toast.error('Label required');
    if (mode === '1' && !zmkKeyId) return toast.error('Pick a ZMK for mode=1');
    setBusy(true);
    try {
      const r = await keysApi.generateSymmetric({
        label, keyType, keyScheme, mode,
        zmkKeyId: mode === '1' ? zmkKeyId : undefined,
        outScheme: mode === '1' ? outScheme : undefined,
      });
      if (r.status === 'OK') {
        toast.success(`Key ${r.keyId} (KCV ${r.kcv})`);
        nav(`/keys/${r.keyId}`);
      } else {
        toast.error(`${r.errCode}: ${r.errText}`);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Generate Symmetric Key</h1>
        <p className="text-xs text-slate-500 mt-1">
          Thales A0/A1 — generates under LMK. Clear key never leaves HSM.
          Optionally returns a ZMK-wrapped copy for transport (mode=1).
        </p>
      </div>

      <div className="space-y-3">
        <Field label="Label">
          <input value={label} onChange={(e) => setLabel(e.target.value)}
                 className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm"
                 placeholder="e.g. zpk-acquirer-jan2026"/>
        </Field>

        <Field label="Key family">
          <select value={keyType} onChange={(e) => setKeyType(e.target.value)}
                  className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm">
            {KEY_TYPES.map((t) => (
              <option key={t.code} value={t.code}>{t.code} — {t.name}: {t.desc}</option>
            ))}
          </select>
        </Field>

        <Field label="Algorithm / length (LMK scheme)">
          <select value={keyScheme} onChange={(e) => setScheme(e.target.value)}
                  className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm">
            {SCHEMES.map((s) => <option key={s.code} value={s.code}>{s.name}</option>)}
          </select>
        </Field>

        <Field label="Mode">
          <select value={mode} onChange={(e) => setMode(e.target.value)}
                  className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm">
            <option value="0">0 — under LMK only</option>
            <option value="1">1 — under LMK + ZMK-wrapped copy</option>
          </select>
        </Field>

        {mode === '1' && (
          <>
            <Field label="ZMK (wraps the new key for transport)">
              <select value={zmkKeyId} onChange={(e) => setZmkKeyId(e.target.value)}
                      className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm">
                <option value="">— pick a ZMK —</option>
                {zmkList.data?.map((k) => (
                  <option key={k.keyId} value={k.keyId}>{k.label} ({k.keyId.slice(0, 8)}…)</option>
                ))}
              </select>
              {zmkList.data?.length === 0 && (
                <div className="text-xs text-amber-600 mt-1">No ZMK in vault. Create one first (mode=0, family ZMK).</div>
              )}
            </Field>

            <Field label="Output scheme (ZMK copy)">
              <select value={outScheme} onChange={(e) => setOut(e.target.value)}
                      className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm">
                {SCHEMES.map((s) => <option key={s.code} value={s.code}>{s.name}</option>)}
              </select>
            </Field>
          </>
        )}
      </div>

      <button onClick={submit} disabled={busy}
              className="rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-2 text-sm text-white">
        {busy ? 'Generating…' : 'Generate'}
      </button>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1">
      <div className="text-xs text-slate-600">{label}</div>
      {children}
    </label>
  );
}
