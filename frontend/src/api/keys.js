import { api } from './client';
export const keysApi = {
    list: (params = {}) => api.get('/keys', { params }).then((r) => r.data),
    get: (id) => api.get(`/keys/${id}`).then((r) => r.data),
    generateRsa: (body) => api.post('/keys/rsa', body).then((r) => r.data),
    generateSymmetric: (body) => api.post('/keys/symmetric', body).then((r) => r.data),
    importRsaWrapped: (body) => api.post('/keys/import-rsa-wrapped', body).then((r) => r.data),
    exportKey: (id, body) => api.post(`/keys/${id}/export`, body).then((r) => r.data),
};
