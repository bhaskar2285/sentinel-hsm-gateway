import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
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
        if (!label.trim())
            return toast.error('Label required');
        setBusy(true);
        try {
            const r = await keysApi.generateRsa({ label, modulusBits: bits, keyType });
            if (r.status === 'OK') {
                toast.success('Key created: ' + r.keyId);
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
    return (_jsxs("div", { className: "max-w-xl space-y-6", children: [_jsx("h1", { className: "text-2xl font-semibold", children: "Generate RSA Key Pair" }), _jsxs("div", { className: "space-y-3", children: [_jsx(Field, { label: "Label", children: _jsx("input", { value: label, onChange: (e) => setLabel(e.target.value), className: "input" }) }), _jsx(Field, { label: "Modulus bits", children: _jsxs("select", { value: bits, onChange: (e) => setBits(Number(e.target.value)), className: "input", children: [_jsx("option", { value: 2048, children: "2048" }), _jsx("option", { value: 3072, children: "3072" }), _jsx("option", { value: 4096, children: "4096" })] }) }), _jsx(Field, { label: "Usage", children: _jsxs("select", { value: keyType, onChange: (e) => setKeyType(e.target.value), className: "input", children: [_jsx("option", { value: "0", children: "Signature only" }), _jsx("option", { value: "1", children: "Encipherment only" }), _jsx("option", { value: "2", children: "Both (sig + encipher)" })] }) })] }), _jsx("button", { onClick: submit, disabled: busy, className: "rounded-md btn-primary disabled:opacity-50", children: busy ? 'Generating…' : 'Generate' })] }));
}
function Field({ label, children }) {
    return (_jsxs("label", { className: "block space-y-1", children: [_jsx("div", { className: "text-xs text-slate-600", children: label }), children] }));
}
