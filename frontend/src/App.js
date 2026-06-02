import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Locate from './pages/Locate';
import KeyCreate from './pages/KeyCreate';
import KeyCreateSym from './pages/KeyCreateSym';
import KeyImport from './pages/KeyImport';
import KeyDetail from './pages/KeyDetail';
import CryptoPlayground from './pages/CryptoPlayground';
import CryptoWizard from './pages/CryptoWizard';
import Pools from './pages/Pools';
import Audit from './pages/Audit';
import RawConsole from './pages/RawConsole';
import AdminRBAC from './pages/AdminRBAC';
import AdminBanks from './pages/AdminBanks';
import Login from './pages/Login';
export default function App() {
    return (_jsxs(Routes, { children: [_jsx(Route, { path: "/login", element: _jsx(Login, {}) }), _jsxs(Route, { element: _jsx(Layout, {}), children: [_jsx(Route, { index: true, element: _jsx(Navigate, { to: "/keys", replace: true }) }), _jsx(Route, { path: "/keys", element: _jsx(Locate, {}) }), _jsx(Route, { path: "/keys/new", element: _jsx(KeyCreate, {}) }), _jsx(Route, { path: "/keys/new-sym", element: _jsx(KeyCreateSym, {}) }), _jsx(Route, { path: "/keys/import", element: _jsx(KeyImport, {}) }), _jsx(Route, { path: "/keys/:keyId", element: _jsx(KeyDetail, {}) }), _jsx(Route, { path: "/crypto", element: _jsx(CryptoPlayground, {}) }), _jsx(Route, { path: "/wizard", element: _jsx(CryptoWizard, {}) }), _jsx(Route, { path: "/pools", element: _jsx(Pools, {}) }), _jsx(Route, { path: "/audit", element: _jsx(Audit, {}) }), _jsx(Route, { path: "/console", element: _jsx(RawConsole, {}) }), _jsx(Route, { path: "/admin/banks", element: _jsx(AdminBanks, {}) }), _jsx(Route, { path: "/admin/rbac", element: _jsx(AdminRBAC, {}) })] })] }));
}
