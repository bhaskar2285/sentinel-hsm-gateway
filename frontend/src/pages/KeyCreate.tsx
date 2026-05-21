import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { keysApi } from '../api/keys';

export default function KeyCreate() {
  const nav = useNavigate();
  const [label, setLabel] = useState('');
  const [bits, setBits] = useState(2048);
  const [keyType, setKeyType] = useState('2');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!label.trim()) return toast.error('Label required');
    setBusy(true);
    try {
      const r = await keysApi.generateRsa({ label, modulusBits: bits, keyType });
      if (r.status === 'OK') {
        toast.success('Key created: ' + r.keyId);
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
      <h1 className="text-2xl font-semibold">Generate RSA Key Pair</h1>
      <div className="space-y-3">
        <Field label="Label">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="input"
          />
        </Field>
        <Field label="Modulus bits">
          <select
            value={bits}
            onChange={(e) => setBits(Number(e.target.value))}
            className="input"
          >
            <option value={2048}>2048</option>
            <option value={3072}>3072</option>
            <option value={4096}>4096</option>
          </select>
        </Field>
        <Field label="Usage">
          <select
            value={keyType}
            onChange={(e) => setKeyType(e.target.value)}
            className="input"
          >
            <option value="0">Signature only</option>
            <option value="1">Encipherment only</option>
            <option value="2">Both (sig + encipher)</option>
          </select>
        </Field>
      </div>
      <button
        onClick={submit}
        disabled={busy}
        className="rounded-md btn-primary disabled:opacity-50"
      >
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
