import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, ShieldCheck, AlertCircle, ChevronDown } from 'lucide-react';
import { api } from '../api/client';

export default function Login() {
  const [loginname, setLoginname]   = useState('');
  const [password, setPassword]     = useState('');
  const [error, setError]           = useState('');
  const [busy, setBusy]             = useState(false);
  const [showAdvanced, setShowAdv]  = useState(false);
  const [pasteToken, setPasteToken] = useState('');
  const nav = useNavigate();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!loginname || !password) { setError('Username and password required'); return; }
    setBusy(true);
    try {
      const r = await api.post('/auth/login', { loginname, password }, { baseURL: '/api/v1' });
      if (r.data?.success) {
        localStorage.setItem('sentinel.jwt', r.data.token);
        localStorage.setItem('sentinel.user', JSON.stringify({
          loginname,
          staffId:  r.data.staffId,
          bankId:   r.data.bankId,
          bankCode: r.data.bankCode,
        }));
        nav('/keys');
      } else {
        setError(r.data?.reason ?? 'Login failed');
      }
    } catch (err: any) {
      setError(err?.response?.data?.reason ?? err?.message ?? 'Network error');
    } finally {
      setBusy(false);
    }
  };

  const onPasteToken = () => {
    if (!pasteToken.trim()) return;
    localStorage.setItem('sentinel.jwt', pasteToken.trim());
    nav('/keys');
  };

  return (
    <div className="min-h-full grid lg:grid-cols-[1fr_520px]">
      <div className="hidden lg:flex flex-col justify-between bg-slate-900 atmo text-slate-100 p-12 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-900 to-sky-950/60" />
        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center backdrop-blur">
              <Lock size={18} className="text-sky-400" strokeWidth={2.5} />
            </div>
            <div>
              <div className="wordmark text-white text-xl leading-none">Sentinel</div>
              <div className="text-[11px] uppercase tracking-[0.15em] text-slate-400 mt-1">HSM Gateway · ISC</div>
            </div>
          </div>
        </div>

        <div className="relative z-10 space-y-5 max-w-md">
          <h1 className="font-serif italic text-4xl text-white leading-tight">
            Keys never leave the boundary.
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            A vendor-neutral HSM gateway for Thales payShield and Utimaco fleets.
            ANSI X9.143 key blocks, ISO 8583-grade audit, ISC SAM authentication
            with per-bank LDAP or Active Directory binding.
          </p>
          <div className="flex gap-2 flex-wrap pt-2">
            <span className="badge-info">TR-31 · X9.143</span>
            <span className="badge-info">FIPS 140-3 L3</span>
            <span className="badge-info">PCI HSM v3</span>
          </div>
        </div>

        <div className="relative z-10 text-[11px] text-slate-500 font-mono">
          v0.1 · build {new Date().getFullYear()}
        </div>
      </div>

      <div className="flex items-center justify-center p-8 lg:p-12 bg-white">
        <div className="w-full max-w-sm space-y-7">
          <div className="lg:hidden flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center">
              <Lock size={16} className="text-sky-400" strokeWidth={2.5} />
            </div>
            <div className="wordmark text-lg">Sentinel</div>
          </div>

          <div>
            <h2 className="text-2xl font-semibold text-slate-900 tracking-tight">Sign in</h2>
            <p className="text-sm text-slate-500 mt-1">Access your bank tenant.</p>
          </div>

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="label">Username</label>
              <input
                type="text"
                autoComplete="username"
                value={loginname}
                onChange={(e) => setLoginname(e.target.value)}
                autoFocus
                className="input"
                placeholder="admin"
              />
            </div>

            <div>
              <label className="label">Password</label>
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg bg-rose-50 border border-rose-200 px-3 py-2.5 animate-fade-up">
                <AlertCircle size={14} className="text-rose-600 mt-0.5 shrink-0" />
                <div className="text-xs text-rose-700 leading-snug">{error}</div>
              </div>
            )}

            <button
              type="submit"
              disabled={busy || !loginname || !password}
              className="btn-primary w-full py-2.5"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <div className="pt-5 border-t border-slate-200">
            <button
              onClick={() => setShowAdv(!showAdvanced)}
              className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition-colors"
            >
              <ChevronDown size={12} className={`transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
              Advanced · paste session token
            </button>
            {showAdvanced && (
              <div className="mt-3 space-y-2 animate-fade-up">
                <textarea
                  value={pasteToken}
                  onChange={(e) => setPasteToken(e.target.value)}
                  rows={3}
                  className="textarea text-xs"
                  placeholder="eyJhbGciOi… or 64-hex session"
                />
                <button onClick={onPasteToken} className="btn-secondary w-full text-xs py-1.5">
                  Use this token
                </button>
                <p className="text-[10px] text-slate-400">SSO bridge from xenticate-auth · dev only.</p>
              </div>
            )}
          </div>

          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <ShieldCheck size={11} />
            <span>ISC SAM · DB · LDAP · MSAD</span>
          </div>
        </div>
      </div>
    </div>
  );
}
