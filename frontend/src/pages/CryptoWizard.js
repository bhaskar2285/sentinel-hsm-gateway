import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from 'react';
import { Check, ChevronDown, Loader2, Play, RotateCcw } from 'lucide-react';
import { api } from '../api/client';
const STEPS = [
    { key: 'genZmk', title: 'Generate ZMK', cmd: 'A0/A1', spec: 'payShield p.38', desc: 'Mint a Zone Master Key under LMK. ZMK wraps other keys for transport.' },
    { key: 'genZpk', title: 'Generate ZPK + wrap', cmd: 'A0/A1', spec: 'mode=1', desc: 'Mint a Zone PIN Key, also return a copy wrapped under the ZMK.' },
    { key: 'exportTr31', title: 'TR-31 Key Block export', cmd: 'B4/B5', spec: 'X9.143', desc: 'Wrap the ZPK in a TR-31 Format D block bound under a KBPK (here, the ZMK).' },
    { key: 'encrypt', title: 'Encrypt sample data', cmd: 'M0/M1', spec: 'p.377', desc: 'Encrypt 16 bytes of plaintext under the ZPK. AES/3DES decided by scheme.' },
    { key: 'decrypt', title: 'Decrypt round-trip', cmd: 'M2/M3', spec: 'p.384', desc: 'Decrypt the ciphertext back to plaintext — closes the loop.' },
];
export default function CryptoWizard() {
    const [active, setActive] = useState('genZmk');
    const [state, setState] = useState({});
    const [busy, setBusy] = useState(null);
    const [err, setErr] = useState({});
    const ts = () => new Date().toISOString().slice(11, 19).replace(/:/g, '');
    const reset = () => { setState({}); setErr({}); setActive('genZmk'); };
    const run = async (step) => {
        setBusy(step);
        setErr(e => ({ ...e, [step]: undefined }));
        try {
            if (step === 'genZmk') {
                const r = await api.post('/keys/symmetric', {
                    label: `wizard-zmk-${ts()}`, keyType: '000', keyScheme: 'U', mode: '0',
                }, { baseURL: '/api/v1' });
                if (r.data.status !== 'OK')
                    throw new Error(`${r.data.errCode}: ${r.data.errText}`);
                setState(s => ({ ...s, zmk: { keyId: r.data.keyId, kcv: r.data.kcv, label: `wizard-zmk-${ts()}` } }));
                setActive('genZpk');
            }
            else if (step === 'genZpk') {
                if (!state.zmk)
                    throw new Error('Need a ZMK first');
                const r = await api.post('/keys/symmetric', {
                    label: `wizard-zpk-${ts()}`, keyType: '001', keyScheme: 'U', mode: '1',
                    zmkKeyId: state.zmk.keyId, outScheme: 'U',
                }, { baseURL: '/api/v1' });
                if (r.data.status !== 'OK')
                    throw new Error(`${r.data.errCode}: ${r.data.errText}`);
                setState(s => ({ ...s, zpk: { keyId: r.data.keyId, kcv: r.data.kcv, label: `wizard-zpk-${ts()}`, underZmk: r.data.keyUnderZmk } }));
                setActive('exportTr31');
            }
            else if (step === 'exportTr31') {
                if (!state.zpk || !state.zmk)
                    throw new Error('Need ZPK and ZMK');
                const r = await api.post(`/keys/${state.zpk.keyId}/export`, {
                    format: 'TR31_D', kbpkKeyId: state.zmk.keyId,
                    usage2: 'P0', algo1: 'T', mode1: 'E', export1: 'E',
                }, { baseURL: '/api/v1' });
                if (r.data.status !== 'OK')
                    throw new Error(`${r.data.errCode}: ${r.data.errText}`);
                setState(s => ({ ...s, tr31: { keyBlock: r.data.keyBlock } }));
                setActive('encrypt');
            }
            else if (step === 'encrypt') {
                if (!state.zpk)
                    throw new Error('Need ZPK');
                const r = await api.post('/crypto/encrypt', {
                    keyId: state.zpk.keyId, mode: '01',
                    iv: '00000000000000000000000000000000',
                    plaintextHex: '48656C6C6F2C2073656E74696E656C21', // "Hello, sentinel!"
                }, { baseURL: '/api/v1' });
                if (r.data.status !== 'OK')
                    throw new Error(`${r.data.errCode}: ${r.data.errText}`);
                setState(s => ({ ...s, encrypt: { ciphertextHex: r.data.ciphertextHex } }));
                setActive('decrypt');
            }
            else if (step === 'decrypt') {
                if (!state.zpk || !state.encrypt)
                    throw new Error('Need ciphertext');
                const r = await api.post('/crypto/decrypt', {
                    keyId: state.zpk.keyId, mode: '01',
                    iv: '00000000000000000000000000000000',
                    ciphertextHex: state.encrypt.ciphertextHex,
                }, { baseURL: '/api/v1' });
                if (r.data.status !== 'OK')
                    throw new Error(`${r.data.errCode}: ${r.data.errText}`);
                setState(s => ({ ...s, decrypt: { plaintextHex: r.data.plaintextHex } }));
            }
        }
        catch (e) {
            setErr(prev => ({ ...prev, [step]: e?.response?.data?.errText ?? e?.message ?? 'failed' }));
        }
        finally {
            setBusy(null);
        }
    };
    const runAll = async () => {
        reset();
        // sequential
        const keys = ['genZmk', 'genZpk', 'exportTr31', 'encrypt', 'decrypt'];
        for (const k of keys) {
            setActive(k);
            await run(k);
            // bail if last step errored — peek state after run? simpler: check err after a microtask
            await new Promise(r => setTimeout(r, 50));
        }
    };
    const isDone = (k) => {
        if (k === 'genZmk')
            return !!state.zmk;
        if (k === 'genZpk')
            return !!state.zpk;
        if (k === 'exportTr31')
            return !!state.tr31;
        if (k === 'encrypt')
            return !!state.encrypt;
        if (k === 'decrypt')
            return !!state.decrypt;
        return false;
    };
    const finalRoundtripOk = state.decrypt?.plaintextHex === '48656C6C6F2C2073656E74696E656C21';
    return (_jsxs("div", { className: "max-w-5xl space-y-6", children: [_jsxs("div", { className: "flex items-end justify-between", children: [_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold tracking-tight", children: "Crypto Walkthrough" }), _jsx("p", { className: "text-sm text-slate-500 mt-1", children: "End-to-end Thales lifecycle: generate ZMK \u2192 wrap ZPK under it \u2192 export TR-31 \u2192 encrypt \u2192 decrypt round-trip. Clear keys never leave the HSM boundary." })] }), _jsxs("div", { className: "flex gap-2", children: [_jsxs("button", { onClick: reset, className: "btn-secondary", children: [_jsx(RotateCcw, { size: 14 }), " Reset"] }), _jsxs("button", { onClick: runAll, className: "btn-primary", disabled: !!busy, children: [_jsx(Play, { size: 14 }), " Run all"] })] })] }), _jsx("ol", { className: "space-y-3", children: STEPS.map((step, idx) => {
                    const done = isDone(step.key);
                    const open = active === step.key;
                    const running = busy === step.key;
                    const stepErr = err[step.key];
                    return (_jsxs("li", { className: `card overflow-hidden transition-colors ${done ? 'border-emerald-200' : ''}`, children: [_jsxs("button", { onClick: () => setActive(step.key), className: "w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-slate-50 transition-colors", children: [_jsx("div", { className: `shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold
                                ${done ? 'bg-emerald-500 text-white'
                                            : open ? 'bg-sky-600 text-white shadow-sm'
                                                : 'bg-slate-100 text-slate-600 ring-1 ring-slate-200'}`, children: done ? _jsx(Check, { size: 14, strokeWidth: 3 }) : idx + 1 }), _jsxs("div", { className: "flex-1", children: [_jsxs("div", { className: "flex items-baseline gap-2", children: [_jsx("span", { className: "font-medium text-slate-900", children: step.title }), _jsx("span", { className: "chip-mono", children: step.cmd }), _jsx("span", { className: "text-[10px] text-slate-400 font-mono", children: step.spec })] }), _jsx("div", { className: "text-xs text-slate-500 mt-0.5", children: step.desc })] }), _jsx(ChevronDown, { size: 16, className: `text-slate-400 transition-transform ${open ? 'rotate-180' : ''}` })] }), open && (_jsxs("div", { className: "px-5 pb-5 border-t border-slate-200 bg-slate-50/50", children: [_jsx("div", { className: "pt-4 flex gap-2", children: _jsx("button", { onClick: () => run(step.key), disabled: running, className: "btn-primary text-xs", children: running ? _jsxs(_Fragment, { children: [_jsx(Loader2, { size: 12, className: "animate-spin" }), " Running\u2026"] }) : _jsxs(_Fragment, { children: ["Run ", step.cmd] }) }) }), stepErr && (_jsx("div", { className: "mt-3 rounded-lg bg-rose-50 border border-rose-200 px-3 py-2 text-xs text-rose-700", children: stepErr })), _jsx(ResultPanel, { stepKey: step.key, state: state, finalOk: finalRoundtripOk })] }))] }, step.key));
                }) }), state.decrypt && (_jsxs("div", { className: `card px-5 py-4 ${finalRoundtripOk ? 'border-emerald-300 bg-emerald-50' : 'border-rose-300 bg-rose-50'}`, children: [_jsxs("div", { className: "flex items-center gap-2", children: [_jsx(Check, { size: 16, className: finalRoundtripOk ? 'text-emerald-600' : 'text-rose-600' }), _jsx("span", { className: "font-medium", children: finalRoundtripOk
                                    ? 'Round-trip verified — plaintext recovered byte-for-byte.'
                                    : 'Round-trip MISMATCH — plaintext does not equal original.' })] }), _jsxs("div", { className: "text-xs text-slate-600 mt-2 font-mono", children: ["decrypted = ", state.decrypt.plaintextHex] })] }))] }));
}
function ResultPanel({ stepKey, state, finalOk }) {
    if (stepKey === 'genZmk' && state.zmk) {
        return (_jsx(KVPanel, { rows: [
                ['Key ID', state.zmk.keyId],
                ['Label', state.zmk.label],
                ['Family', '000 (ZMK)'],
                ['KCV', state.zmk.kcv],
            ] }));
    }
    if (stepKey === 'genZpk' && state.zpk) {
        return (_jsx(KVPanel, { rows: [
                ['Key ID', state.zpk.keyId],
                ['Label', state.zpk.label],
                ['Family', '001 (ZPK)'],
                ['KCV', state.zpk.kcv],
                ['Under ZMK', state.zpk.underZmk ?? '(mode 0 — no ZMK copy returned)'],
            ] }));
    }
    if (stepKey === 'exportTr31' && state.tr31) {
        return (_jsxs("div", { className: "mt-4 space-y-1", children: [_jsx("div", { className: "text-[11px] uppercase tracking-wider text-slate-500 font-semibold", children: "TR-31 Format D Key Block" }), _jsx("pre", { className: "rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-mono break-all whitespace-pre-wrap", children: state.tr31.keyBlock }), _jsxs("div", { className: "text-[10px] text-slate-500 mt-1", children: ["ASCII envelope: ", _jsx("code", { className: "chip-mono", children: "D0096" }), " = version D, 96 bytes \u00B7", _jsx("code", { className: "chip-mono ml-1", children: "P0TE" }), " = PIN-encrypt usage, 3DES, encrypt-only, exportable \u00B7 MAC bound via AES-CMAC."] })] }));
    }
    if (stepKey === 'encrypt' && state.encrypt) {
        return (_jsx(KVPanel, { rows: [
                ['Plaintext', '48656C6C6F2C2073656E74696E656C21'],
                ['ASCII', '"Hello, sentinel!"'],
                ['IV', '00000000000000000000000000000000'],
                ['Ciphertext', state.encrypt.ciphertextHex],
            ] }));
    }
    if (stepKey === 'decrypt' && state.decrypt) {
        return (_jsx(KVPanel, { rows: [
                ['Recovered hex', state.decrypt.plaintextHex],
                ['Recovered ASCII', hexToAscii(state.decrypt.plaintextHex)],
                ['Round-trip', finalOk ? 'OK — matches original' : 'MISMATCH'],
            ] }));
    }
    return null;
}
function KVPanel({ rows }) {
    return (_jsx("dl", { className: "mt-4 grid grid-cols-[140px_1fr] gap-x-4 gap-y-1.5 text-xs", children: rows.map(([k, v]) => (_jsxs(_Fragment, { children: [_jsx("dt", { className: "text-slate-500 font-medium", children: k }), _jsx("dd", { className: "font-mono break-all text-slate-900", children: v })] }))) }));
}
function hexToAscii(hex) {
    if (!hex)
        return '';
    let out = '';
    for (let i = 0; i < hex.length; i += 2) {
        const c = parseInt(hex.substr(i, 2), 16);
        out += (c >= 32 && c < 127) ? String.fromCharCode(c) : '·';
    }
    return out;
}
