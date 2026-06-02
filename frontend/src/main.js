import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { Toaster } from 'sonner';
import App from './App';
import './index.css';
const qc = new QueryClient({
    defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
});
ReactDOM.createRoot(document.getElementById('root')).render(_jsx(React.StrictMode, { children: _jsx(BrowserRouter, { children: _jsxs(QueryClientProvider, { client: qc, children: [_jsx(App, {}), _jsx(Toaster, { richColors: true, position: "top-right" })] }) }) }));
