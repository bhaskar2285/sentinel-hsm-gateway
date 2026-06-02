import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { toast } from 'sonner';
import { keysApi } from '../api/keys';
const KBPK_TYPES = new Set(['ZMK', 'KBPK', 'TMK']);
export default function KeyDetail() {
    const { keyId } = useParams();
    const { data, isLoading } = useQuery({
        queryKey: ['key', keyId],
        queryFn: () => keysApi.get(keyId),
        enabled: !!keyId,
    });
    const all = useQuery({
        queryKey: ['keys'],
        queryFn: () => keysApi.list(),
    });
    const [format, setFormat] = useState('TR31_D');
    const [kbpkKeyId, setKbpkKeyId] = useState('');
    const [exported, setExported] = useState('');
    const [busy, setBusy] = useState(false);
    const kbpkCandidates = (all.data ?? []).filter((k) => KBPK_TYPES.has(k.keyType) && k.keyId !== keyId);
    const doExport = async () => {
        if (!keyId)
            return;
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
            }
            else {
                toast.error(`${r.errCode}: ${r.errText}`);
            }
        }
        finally {
            setBusy(false);
        }
    };
    if (isLoading)
        return _jsx("div", { className: "text-slate-500", children: "Loading\u2026" });
    if (!data)
        return _jsx("div", { children: "Not found" });
    return (_jsxs("div", { className: "max-w-3xl space-y-6", children: [_jsxs("div", { className: "flex items-baseline justify-between", children: [_jsx("h1", { className: "text-2xl font-semibold", children: data.label }), _jsx("span", { className: "text-xs px-2 py-1 rounded bg-slate-100", children: data.status })] }), _jsxs("div", { className: "grid grid-cols-2 gap-4 text-sm", children: [_jsx(Info, { k: "Key ID", v: data.keyId, mono: true }), _jsx(Info, { k: "Type", v: data.keyType }), _jsx(Info, { k: "Algorithm", v: data.algo }), _jsx(Info, { k: "Bits", v: data.keyLengthBits }), _jsx(Info, { k: "Usage", v: data.usage }), _jsx(Info, { k: "KCV", v: data.kcv, mono: true }), _jsx(Info, { k: "Owner", v: data.ownerUserId }), _jsx(Info, { k: "Vendor", v: data.vendorOrigin }), _jsx(Info, { k: "Version", v: data.version }), _jsx(Info, { k: "Created", v: data.createdAt })] }), _jsxs("div", { className: "space-y-3 border-t border-slate-200 pt-4", children: [_jsxs("div", { children: [_jsxs("h2", { className: "text-lg font-medium", children: ["Export ", _jsx("span", { className: "text-xs font-mono text-slate-500", children: "[A8/A9]" })] }), _jsx("p", { className: "text-xs text-slate-500 mt-1", children: "Wraps this key under a KBPK / ZMK so it can leave the HSM safely. Raw = LMK-encrypted blob (admin only)." })] }), _jsxs("div", { className: "grid grid-cols-2 gap-3", children: [_jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Format" }), _jsxs("select", { value: format, onChange: (e) => setFormat(e.target.value), className: "input", children: [_jsx("option", { value: "TR31_B", children: "TR-31 Format B (3DES KBPK)" }), _jsx("option", { value: "TR31_D", children: "TR-31 Format D (AES KBPK)" }), _jsx("option", { value: "X9_143", children: "ANSI X9.143" }), _jsx("option", { value: "RAW", children: "Raw (admin only)" })] })] }), _jsxs("label", { children: [_jsx("div", { className: "text-xs text-slate-600 mb-1", children: "Wrapping key (ZMK / KBPK / TMK)" }), _jsxs("select", { value: kbpkKeyId, onChange: (e) => setKbpkKeyId(e.target.value), disabled: format === 'RAW', className: "input disabled:opacity-40", children: [_jsx("option", { value: "", children: format === 'RAW' ? 'N/A (Raw mode)' : '— pick a key —' }), kbpkCandidates.map((k) => (_jsxs("option", { value: k.keyId, children: [k.label, " (", k.keyType, ")"] }, k.keyId)))] })] })] }), kbpkCandidates.length === 0 && format !== 'RAW' && (_jsx("div", { className: "text-xs text-amber-400", children: "No ZMK/KBPK/TMK in vault. Import one first via \"Import Key\"." })), _jsx("button", { onClick: doExport, disabled: busy, className: "rounded-md btn-primary disabled:opacity-50", children: busy ? 'Exporting…' : 'Export' }), exported && (_jsxs("div", { className: "space-y-1", children: [_jsx("div", { className: "text-xs text-slate-600", children: "Key block" }), _jsx("pre", { className: "rounded-md border border-slate-200 bg-white p-3 text-xs font-mono overflow-auto break-all whitespace-pre-wrap", children: exported })] }))] })] }));
}
function Info({ k, v, mono = false }) {
    return (_jsxs("div", { children: [_jsx("div", { className: "text-xs text-slate-500", children: k }), _jsx("div", { className: mono ? 'font-mono text-xs break-all' : '', children: v ?? '-' })] }));
}
