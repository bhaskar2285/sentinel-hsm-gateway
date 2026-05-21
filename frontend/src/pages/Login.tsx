import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export default function Login() {
  const [loginname, setLoginname] = useState('');
  const [password, setPassword]   = useState('');
  const [error, setError]         = useState('');
  const [busy, setBusy]           = useState(false);
  const [showAdvanced, setShowAdv]= useState(false);
  const [pasteToken, setPasteToken]= useState('');
  const nav = useNavigate();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!loginname || !password) {
      setError('username and password required');
      return;
    }
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
        setError(r.data?.reason ?? 'login failed');
      }
    } catch (err: any) {
      const reason = err?.response?.data?.reason ?? err?.message ?? 'network error';
      setError(reason);
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
    <div className="flex h-full items-center justify-center bg-white">
      <div className="w-96 rounded-lg border border-slate-200 bg-white shadow-sm p-6 space-y-5">
        <div>
          <div className="text-xl font-semibold tracking-tight">Sentinel HSM Console</div>
          <div className="text-xs text-slate-500 mt-1">Sign in to your bank tenant</div>
        </div>

        <form onSubmit={onSubmit} className="space-y-3">
          <label className="block">
            <div className="text-xs text-slate-600 mb-1">Username</div>
            <input
              type="text"
              autoComplete="username"
              value={loginname}
              onChange={(e) => setLoginname(e.target.value)}
              autoFocus
              className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm focus:border-sky-600 focus:outline-none"
              placeholder="admin"
            />
          </label>

          <label className="block">
            <div className="text-xs text-slate-600 mb-1">Password</div>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md bg-white border border-slate-200 px-3 py-2 text-sm focus:border-sky-600 focus:outline-none"
              placeholder="••••••••"
            />
          </label>

          {error && (
            <div className="rounded-md bg-red-50 border border-red-200 text-red-700 text-xs px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy || !loginname || !password}
            className="w-full rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed py-2 text-sm font-medium"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="border-t border-slate-200 pt-3">
          <button
            onClick={() => setShowAdv(!showAdvanced)}
            className="text-xs text-slate-500 hover:text-slate-700"
          >
            {showAdvanced ? '↑ Hide' : '↓ Advanced: paste JWT/session token'}
          </button>
          {showAdvanced && (
            <div className="mt-2 space-y-2">
              <textarea
                value={pasteToken}
                onChange={(e) => setPasteToken(e.target.value)}
                rows={3}
                className="w-full rounded-md bg-white border border-slate-200 p-2 font-mono text-xs"
                placeholder="eyJhbGciOi… or session hex"
              />
              <button
                onClick={onPasteToken}
                className="w-full rounded-md bg-slate-100 hover:bg-slate-200 py-1.5 text-xs"
              >
                Use this token
              </button>
              <div className="text-[10px] text-slate-400">
                For dev / SSO bridge from xenticate-auth.
              </div>
            </div>
          )}
        </div>

        <div className="text-[10px] text-slate-400 text-center pt-2 border-t border-slate-200">
          ISC SAM authentication · auth method picked per bank (DB / LDAP / MSAD)
        </div>
      </div>
    </div>
  );
}
