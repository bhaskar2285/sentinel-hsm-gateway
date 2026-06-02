import axios from 'axios';
export const api = axios.create({
    baseURL: import.meta.env.VITE_API_BASE ?? '/api/v1',
    timeout: 30_000,
});
api.interceptors.request.use((cfg) => {
    const token = localStorage.getItem('sentinel.jwt');
    if (token)
        cfg.headers.Authorization = `Bearer ${token}`;
    try {
        const u = JSON.parse(localStorage.getItem('sentinel.user') ?? 'null');
        if (u?.bankId)
            cfg.headers['X-Bank-Id'] = String(u.bankId);
        if (u?.branchId)
            cfg.headers['X-Branch-Id'] = String(u.branchId);
    }
    catch { /* ignore */ }
    return cfg;
});
api.interceptors.response.use((r) => r, (err) => {
    if (err?.response?.status === 401) {
        localStorage.removeItem('sentinel.jwt');
        window.location.assign('/login');
    }
    return Promise.reject(err);
});
