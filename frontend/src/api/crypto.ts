import { api } from './client';

export const cryptoApi = {
  decrypt: (body: {
    keyId: string;
    ciphertextHex: string;
    mode?: string;
    iv?: string;
    inputFormat?: string;
    outputFormat?: string;
  }) => api.post('/crypto/decrypt', body).then((r) => r.data),
};
