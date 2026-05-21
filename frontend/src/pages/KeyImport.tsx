import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { keysApi } from '../api/keys';

export default function KeyImport() {
  const nav = useNavigate();
  const [label, setLabel] = useState('');
  const [keyType, setKeyType] = useState('ZPK');
  const [wrappingPublicKey, setWpk] = useState('');
  const [wrappedKey, setWk] = useState('');
  const [mode, setMode] = useState('0');
  const [hashId, setHashId] = useState('01');
  const [usage, setUsage] = useState('ENCRYPT,DECRYPT');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!label.trim()) return toast.error('Label required');
    if (!wrappingPublicKey.trim() || !wrappedKey.trim()) return toast.error('Both keys (hex) required');
    setBusy(true);
    try {
      const r = await keysApi.importRsaWrapped({
        label,
        wrappingPublicKey: wrappingPublicKey.replace(/\s+/g, ''),
        wrappedKey: wrappedKey.replace(/\s+/g, ''),
        mode,
        hashId,
        keyType,
        usage,
      });
      if (r.status === 'OK') {
        toast.success('Imported: ' + r.keyId);
        nav(`/keys/${r.keyId}`);
      } else {
        toast.error(`${r.errCode}: ${r.errText}`);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Import Key (under RSA Public Key)</h1>
        <div className="text-xs text-slate-500 mt-1">Thales GI / GJ — payShield 10K spec p.182</div>
      </div>
      <div className="space-y-3">
        <Field label="Label">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. zpk-prod-01"
            className="input"
          />
        </Field>
        <Field label="Key Type">
          <select
            value={keyType}
            onChange={(e) => setKeyType(e.target.value)}
            className="input"
          >
            <option>ZPK</option>
            <option>ZMK</option>
            <option>TMK</option>
            <option>TPK</option>
            <option>TAK</option>
            <option>BDK</option>
            <option>KBPK</option>
            <option>PVK</option>
            <option>CVK</option>
            <option>MAC</option>
          </select>
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Mode">
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="input"
            >
              <option value="0">0 — RSA</option>
              <option value="1">1 — RSA-OAEP</option>
            </select>
          </Field>
          <Field label="Hash ID">
            <select
              value={hashId}
              onChange={(e) => setHashId(e.target.value)}
              className="input"
            >
              <option value="01">01 — SHA-1</option>
              <option value="02">02 — SHA-224</option>
              <option value="03">03 — SHA-256</option>
              <option value="04">04 — SHA-384</option>
              <option value="05">05 — SHA-512</option>
            </select>
          </Field>
        </div>
        <Field label="Wrapping Public Key (hex, DER SubjectPublicKeyInfo)">
          <textarea
            value={wrappingPublicKey}
            onChange={(e) => setWpk(e.target.value)}
            className="textarea h-24 text-xs"
            placeholder="30820122300D06092A864886F70D01010105000382010F00..."
          />
        </Field>
        <Field label="Wrapped Key (hex, RSA-encrypted symmetric key)">
          <textarea
            value={wrappedKey}
            onChange={(e) => setWk(e.target.value)}
            className="textarea h-24 text-xs"
            placeholder="AABBCCDDEEFF00112233445566778899..."
          />
        </Field>
        <Field label="Usage (CSV)">
          <input
            value={usage}
            onChange={(e) => setUsage(e.target.value)}
            className="input font-mono"
          />
        </Field>
      </div>
      <button
        onClick={submit}
        disabled={busy}
        className="rounded-md btn-primary disabled:opacity-50"
      >
        {busy ? 'Importing…' : 'Import'}
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
