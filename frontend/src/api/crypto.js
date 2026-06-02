import { api } from './client';
export const cryptoApi = {
    decrypt: (body) => api.post('/crypto/decrypt', body).then((r) => r.data),
};
