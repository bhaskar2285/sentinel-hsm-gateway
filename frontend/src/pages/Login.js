import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, ShieldCheck, AlertCircle, ChevronDown } from 'lucide-react';
import { api } from '../api/client';
export default function Login() {
    const [loginname, setLoginname] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const [showAdvanced, setShowAdv] = useState(false);
    const [pasteToken, setPasteToken] = useState('');
    const nav = useNavigate();
    const onSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!loginname || !password) {
            setError('Username and password required');
            return;
        }
        setBusy(true);
        try {
            const r = await api.post('/auth/login', { loginname, password }, { baseURL: '/api/v1' });
            if (r.data?.success) {
                localStorage.setItem('sentinel.jwt', r.data.token);
                localStorage.setItem('sentinel.user', JSON.stringify({
                    loginname,
                    staffId: r.data.staffId,
                    bankId: r.data.bankId,
                    bankCode: r.data.bankCode,
                }));
                nav('/keys');
            }
            else {
                setError(r.data?.reason ?? 'Login failed');
            }
        }
        catch (err) {
            setError(err?.response?.data?.reason ?? err?.message ?? 'Network error');
        }
        finally {
            setBusy(false);
        }
    };
    const onPasteToken = () => {
        if (!pasteToken.trim())
            return;
        localStorage.setItem('sentinel.jwt', pasteToken.trim());
        nav('/keys');
    };
    return (_jsxs("div", { className: "min-h-full grid lg:grid-cols-[1fr_520px]", children: [_jsxs("div", { className: "hidden lg:flex flex-col justify-between bg-slate-900 atmo text-slate-100 p-12 relative overflow-hidden", children: [_jsx("div", { className: "absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-900 to-sky-950/60" }), _jsx("div", { className: "relative z-10", children: _jsxs("div", { className: "flex items-center gap-3", children: [_jsx("div", { className: "w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center backdrop-blur", children: _jsx(Lock, { size: 18, className: "text-sky-400", strokeWidth: 2.5 }) }), _jsxs("div", { children: [_jsx("div", { className: "wordmark text-white text-xl leading-none", children: "Sentinel" }), _jsx("div", { className: "text-[11px] uppercase tracking-[0.15em] text-slate-400 mt-1", children: "HSM Gateway \u00B7 ISC" })] })] }) }), _jsxs("div", { className: "relative z-10 space-y-5 max-w-md", children: [_jsx("h1", { className: "font-serif italic text-4xl text-white leading-tight", children: "Keys never leave the boundary." }), _jsx("p", { className: "text-sm text-slate-300 leading-relaxed", children: "A vendor-neutral HSM gateway for Thales payShield and Utimaco fleets. ANSI X9.143 key blocks, ISO 8583-grade audit, ISC SAM authentication with per-bank LDAP or Active Directory binding." }), _jsxs("div", { className: "flex gap-2 flex-wrap pt-2", children: [_jsx("span", { className: "badge-info", children: "TR-31 \u00B7 X9.143" }), _jsx("span", { className: "badge-info", children: "FIPS 140-3 L3" }), _jsx("span", { className: "badge-info", children: "PCI HSM v3" })] })] }), _jsxs("div", { className: "relative z-10 text-[11px] text-slate-500 font-mono", children: ["v0.1 \u00B7 build ", new Date().getFullYear()] })] }), _jsx("div", { className: "flex items-center justify-center p-8 lg:p-12 bg-white", children: _jsxs("div", { className: "w-full max-w-sm space-y-7", children: [_jsxs("div", { className: "lg:hidden flex items-center gap-2.5", children: [_jsx("div", { className: "w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center", children: _jsx(Lock, { size: 16, className: "text-sky-400", strokeWidth: 2.5 }) }), _jsx("div", { className: "wordmark text-lg", children: "Sentinel" })] }), _jsxs("div", { children: [_jsx("h2", { className: "text-2xl font-semibold text-slate-900 tracking-tight", children: "Sign in" }), _jsx("p", { className: "text-sm text-slate-500 mt-1", children: "Access your bank tenant." })] }), _jsxs("form", { onSubmit: onSubmit, className: "space-y-4", children: [_jsxs("div", { children: [_jsx("label", { className: "label", children: "Username" }), _jsx("input", { type: "text", autoComplete: "username", value: loginname, onChange: (e) => setLoginname(e.target.value), autoFocus: true, className: "input", placeholder: "admin" })] }), _jsxs("div", { children: [_jsx("label", { className: "label", children: "Password" }), _jsx("input", { type: "password", autoComplete: "current-password", value: password, onChange: (e) => setPassword(e.target.value), className: "input", placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" })] }), error && (_jsxs("div", { className: "flex items-start gap-2 rounded-lg bg-rose-50 border border-rose-200 px-3 py-2.5 animate-fade-up", children: [_jsx(AlertCircle, { size: 14, className: "text-rose-600 mt-0.5 shrink-0" }), _jsx("div", { className: "text-xs text-rose-700 leading-snug", children: error })] })), _jsx("button", { type: "submit", disabled: busy || !loginname || !password, className: "btn-primary w-full py-2.5", children: busy ? 'Signing in…' : 'Sign in' })] }), _jsxs("div", { className: "pt-5 border-t border-slate-200", children: [_jsxs("button", { onClick: () => setShowAdv(!showAdvanced), className: "flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition-colors", children: [_jsx(ChevronDown, { size: 12, className: `transition-transform ${showAdvanced ? 'rotate-180' : ''}` }), "Advanced \u00B7 paste session token"] }), showAdvanced && (_jsxs("div", { className: "mt-3 space-y-2 animate-fade-up", children: [_jsx("textarea", { value: pasteToken, onChange: (e) => setPasteToken(e.target.value), rows: 3, className: "textarea text-xs", placeholder: "eyJhbGciOi\u2026 or 64-hex session" }), _jsx("button", { onClick: onPasteToken, className: "btn-secondary w-full text-xs py-1.5", children: "Use this token" }), _jsx("p", { className: "text-[10px] text-slate-400", children: "SSO bridge from xenticate-auth \u00B7 dev only." })] }))] }), _jsxs("div", { className: "flex items-center gap-1.5 text-[11px] text-slate-400", children: [_jsx(ShieldCheck, { size: 11 }), _jsx("span", { children: "ISC SAM \u00B7 DB \u00B7 LDAP \u00B7 MSAD" })] })] }) })] }));
}
