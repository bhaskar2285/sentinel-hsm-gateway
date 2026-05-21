import axios from 'axios';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? '/api/v1',
  timeout: 30_000,
});

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('sentinel.jwt');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem('sentinel.jwt');
      window.location.assign('/login');
    }
    return Promise.reject(err);
  }
);
