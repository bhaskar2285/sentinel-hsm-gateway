import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { keysApi } from '../api/keys';
const KEY_TYPES = [
    { code: '000', name: 'ZMK', desc: 'Zone Master Key — wraps other keys for transport' },
    { code: '001', name: 'ZPK', desc: 'Zone PIN Key — encrypts PIN blocks on the wire' },
    { code: '002', name: 'KBPK', desc: 'Key Block Protection Key — TR-31 wrap KEK' },
    { code: '008', name: 'TMK', desc: 'Terminal Master Key — POS/ATM injection' },
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
    const [label, setLabel] = useState('');
    const [keyType, setKeyType] = useState('001');
    const [keyScheme, setScheme] = useState('U');
    const [mode, setMode] = useState('0');
    const [zmkKeyId, setZmkKeyId] = useState('');
    const [outScheme, setOut] = useState('U');
    const [busy, setBusy] = useState(false);
    const zmkList = useQuery({
        queryKey: ['keys', 'zmk-list'],
        queryFn: () => keysApi.list({ keyType: 'ZMK' }),
        enabled: mode === '1',
    });
    const submit = async () => {
        if (!label.trim())
            return toast.error('Label required');
        if (mode === '1' && !zmkKeyId)
            return toast.error('Pick a ZMK for mode=1');
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
            }
            else {
                toast.error(`${r.errCode}: ${r.errText}`);
            }
        }
        finally {
            setBusy(false);
        }
    };
    return (_jsxs("div", { className: "max-w-xl space-y-6", children: [_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Generate Symmetric Key" }), _jsx("p", { className: "text-xs text-slate-500 mt-1", children: "Thales A0/A1 \u2014 generates under LMK. Clear key never leaves HSM. Optionally returns a ZMK-wrapped copy for transport (mode=1)." })] }), _jsxs("div", { className: "space-y-3", children: [_jsx(Field, { label: "Label", children: _jsx("input", { value: label, onChange: (e) => setLabel(e.target.value), className: "input", placeholder: "e.g. zpk-acquirer-jan2026" }) }), _jsx(Field, { label: "Key family", children: _jsx("select", { value: keyType, onChange: (e) => setKeyType(e.target.value), className: "input", children: KEY_TYPES.map((t) => (_jsxs("option", { value: t.code, children: [t.code, " \u2014 ", t.name, ": ", t.desc] }, t.code))) }) }), _jsx(Field, { label: "Algorithm / length (LMK scheme)", children: _jsx("select", { value: keyScheme, onChange: (e) => setScheme(e.target.value), className: "input", children: SCHEMES.map((s) => _jsx("option", { value: s.code, children: s.name }, s.code)) }) }), _jsx(Field, { label: "Mode", children: _jsxs("select", { value: mode, onChange: (e) => setMode(e.target.value), className: "input", children: [_jsx("option", { value: "0", children: "0 \u2014 under LMK only" }), _jsx("option", { value: "1", children: "1 \u2014 under LMK + ZMK-wrapped copy" })] }) }), mode === '1' && (_jsxs(_Fragment, { children: [_jsxs(Field, { label: "ZMK (wraps the new key for transport)", children: [_jsxs("select", { value: zmkKeyId, onChange: (e) => setZmkKeyId(e.target.value), className: "input", children: [_jsx("option", { value: "", children: "\u2014 pick a ZMK \u2014" }), zmkList.data?.map((k) => (_jsxs("option", { value: k.keyId, children: [k.label, " (", k.keyId.slice(0, 8), "\u2026)"] }, k.keyId)))] }), zmkList.data?.length === 0 && (_jsx("div", { className: "text-xs text-amber-600 mt-1", children: "No ZMK in vault. Create one first (mode=0, family ZMK)." }))] }), _jsx(Field, { label: "Output scheme (ZMK copy)", children: _jsx("select", { value: outScheme, onChange: (e) => setOut(e.target.value), className: "input", children: SCHEMES.map((s) => _jsx("option", { value: s.code, children: s.name }, s.code)) }) })] }))] }), _jsx("button", { onClick: submit, disabled: busy, className: "rounded-md btn-primary disabled:opacity-50 text-white", children: busy ? 'Generating…' : 'Generate' })] }));
}
function Field({ label, children }) {
    return (_jsxs("label", { className: "block space-y-1", children: [_jsx("div", { className: "text-xs text-slate-600", children: label }), children] }));
}
