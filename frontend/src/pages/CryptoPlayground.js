import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { cryptoApi } from '../api/crypto';
import { keysApi } from '../api/keys';
export default function CryptoPlayground() {
    const [keyId, setKeyId] = useState('');
    const [mode, setMode] = useState('01');
    const [iv, setIv] = useState('');
    const [ciphertext, setCiphertext] = useState('');
    const [plaintext, setPlaintext] = useState('');
    const { data: keys = [] } = useQuery({
        queryKey: ['keys'],
        queryFn: () => keysApi.list(),
    });
    const run = async () => {
        const r = await cryptoApi.decrypt({ keyId, ciphertextHex: ciphertext, mode, iv });
        if (r.status === 'OK') {
            setPlaintext(r.plaintextHex);
            toast.success('Decrypted');
        }
        else {
            toast.error(`${r.errCode}: ${r.errText}`);
        }
    };
    return (_jsxs("div", { className: "max-w-2xl space-y-4", children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Crypto Playground \u2014 Decrypt" }), _jsxs("div", { children: [_jsx("div", { className: "label", children: "Key" }), _jsxs("select", { value: keyId, onChange: (e) => setKeyId(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 pick a key \u2014" }), keys.map((k) => (_jsxs("option", { value: k.keyId, children: [k.label, " (", k.keyType, ") \u00B7 KCV ", k.kcv ?? '—'] }, k.keyId)))] })] }), _jsxs("div", { className: "grid grid-cols-2 gap-2", children: [_jsxs("select", { value: mode, onChange: (e) => setMode(e.target.value), className: "input", children: [_jsx("option", { value: "00", children: "ECB" }), _jsx("option", { value: "01", children: "CBC" }), _jsx("option", { value: "02", children: "CFB" })] }), _jsx("input", { value: iv, onChange: (e) => setIv(e.target.value), placeholder: "IV (hex, CBC only)", className: "input font-mono" })] }), _jsx("textarea", { value: ciphertext, onChange: (e) => setCiphertext(e.target.value), placeholder: "Ciphertext (hex)", className: "textarea h-24 text-xs" }), _jsx("button", { onClick: run, className: "rounded-md btn-primary", children: "Decrypt" }), plaintext && (_jsxs("div", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Plaintext (hex)" }), _jsx("pre", { className: "rounded-md border border-slate-200 bg-white p-3 text-xs font-mono", children: plaintext })] }))] }));
}
