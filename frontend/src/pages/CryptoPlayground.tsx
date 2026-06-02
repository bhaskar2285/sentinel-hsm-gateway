import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { cryptoApi } from '../api/crypto';
import { keysApi, KeySummary } from '../api/keys';

export default function CryptoPlayground() {
  const [keyId, setKeyId] = useState('');
  const [mode, setMode] = useState('01');
  const [iv, setIv] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [plaintext, setPlaintext] = useState('');

  const { data: keys = [] } = useQuery<KeySummary[]>({
    queryKey: ['keys'],
    queryFn: () => keysApi.list(),
  });

  const run = async () => {
    const r = await cryptoApi.decrypt({ keyId, ciphertextHex: ciphertext, mode, iv });
    if (r.status === 'OK') {
      setPlaintext(r.plaintextHex);
      toast.success('Decrypted');
    } else {
      toast.error(`${r.errCode}: ${r.errText}`);
    }
  };

  return (
    <div className="max-w-2xl space-y-4">
      <h1 className="text-2xl font-semibold">Crypto Playground — Decrypt</h1>
      <div>
        <div className="label">Key</div>
        <select
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
          className="input"
        >
          <option value="">— pick a key —</option>
          {keys.map((k) => (
            <option key={k.keyId} value={k.keyId}>
              {k.label} ({k.keyType}) · KCV {k.kcv ?? '—'}
            </option>
          ))}
        </select>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          className="input"
        >
          <option value="00">ECB</option>
          <option value="01">CBC</option>
          <option value="02">CFB</option>
        </select>
        <input
          value={iv}
          onChange={(e) => setIv(e.target.value)}
          placeholder="IV (hex, CBC only)"
          className="input font-mono"
        />
      </div>
      <textarea
        value={ciphertext}
        onChange={(e) => setCiphertext(e.target.value)}
        placeholder="Ciphertext (hex)"
        className="textarea h-24 text-xs"
      />
      <button onClick={run} className="rounded-md btn-primary">
        Decrypt
      </button>
      {plaintext && (
        <div>
          <div className="text-xs text-slate-600 mb-1">Plaintext (hex)</div>
          <pre className="rounded-md border border-slate-200 bg-white p-3 text-xs font-mono">{plaintext}</pre>
        </div>
      )}
    </div>
  );
}
