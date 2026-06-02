import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
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
        if (!label.trim())
            return toast.error('Label required');
        if (!wrappingPublicKey.trim() || !wrappedKey.trim())
            return toast.error('Both keys (hex) required');
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
            }
            else {
                toast.error(`${r.errCode}: ${r.errText}`);
            }
        }
        finally {
            setBusy(false);
        }
    };
    return (_jsxs("div", { className: "max-w-2xl space-y-6", children: [_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Import Key (under RSA Public Key)" }), _jsx("div", { className: "text-xs text-slate-500 mt-1", children: "Thales GI / GJ \u2014 payShield 10K spec p.182" })] }), _jsxs("div", { className: "space-y-3", children: [_jsx(Field, { label: "Label", children: _jsx("input", { value: label, onChange: (e) => setLabel(e.target.value), placeholder: "e.g. zpk-prod-01", className: "input" }) }), _jsx(Field, { label: "Key Type", children: _jsxs("select", { value: keyType, onChange: (e) => setKeyType(e.target.value), className: "input", children: [_jsx("option", { children: "ZPK" }), _jsx("option", { children: "ZMK" }), _jsx("option", { children: "TMK" }), _jsx("option", { children: "TPK" }), _jsx("option", { children: "TAK" }), _jsx("option", { children: "BDK" }), _jsx("option", { children: "KBPK" }), _jsx("option", { children: "PVK" }), _jsx("option", { children: "CVK" }), _jsx("option", { children: "MAC" })] }) }), _jsxs("div", { className: "grid grid-cols-2 gap-2", children: [_jsx(Field, { label: "Mode", children: _jsxs("select", { value: mode, onChange: (e) => setMode(e.target.value), className: "input", children: [_jsx("option", { value: "0", children: "0 \u2014 RSA" }), _jsx("option", { value: "1", children: "1 \u2014 RSA-OAEP" })] }) }), _jsx(Field, { label: "Hash ID", children: _jsxs("select", { value: hashId, onChange: (e) => setHashId(e.target.value), className: "input", children: [_jsx("option", { value: "01", children: "01 \u2014 SHA-1" }), _jsx("option", { value: "02", children: "02 \u2014 SHA-224" }), _jsx("option", { value: "03", children: "03 \u2014 SHA-256" }), _jsx("option", { value: "04", children: "04 \u2014 SHA-384" }), _jsx("option", { value: "05", children: "05 \u2014 SHA-512" })] }) })] }), _jsx(Field, { label: "Wrapping Public Key (hex, DER SubjectPublicKeyInfo)", children: _jsx("textarea", { value: wrappingPublicKey, onChange: (e) => setWpk(e.target.value), className: "textarea h-24 text-xs", placeholder: "30820122300D06092A864886F70D01010105000382010F00..." }) }), _jsx(Field, { label: "Wrapped Key (hex, RSA-encrypted symmetric key)", children: _jsx("textarea", { value: wrappedKey, onChange: (e) => setWk(e.target.value), className: "textarea h-24 text-xs", placeholder: "AABBCCDDEEFF00112233445566778899..." }) }), _jsx(Field, { label: "Usage (CSV)", children: _jsx("input", { value: usage, onChange: (e) => setUsage(e.target.value), className: "input font-mono" }) })] }), _jsx("button", { onClick: submit, disabled: busy, className: "rounded-md btn-primary disabled:opacity-50", children: busy ? 'Importing…' : 'Import' })] }));
}
function Field({ label, children }) {
    return (_jsxs("label", { className: "block space-y-1", children: [_jsx("div", { className: "text-xs text-slate-600", children: label }), children] }));
}
