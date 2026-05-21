import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Locate from './pages/Locate';
import KeyCreate from './pages/KeyCreate';
import KeyCreateSym from './pages/KeyCreateSym';
import KeyImport from './pages/KeyImport';
import KeyDetail from './pages/KeyDetail';
import CryptoPlayground from './pages/CryptoPlayground';
import Pools from './pages/Pools';
import Audit from './pages/Audit';
import RawConsole from './pages/RawConsole';
import AdminRBAC from './pages/AdminRBAC';
import AdminBanks from './pages/AdminBanks';
import Login from './pages/Login';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/keys" replace />} />
        <Route path="/keys" element={<Locate />} />
        <Route path="/keys/new" element={<KeyCreate />} />
        <Route path="/keys/new-sym" element={<KeyCreateSym />} />
        <Route path="/keys/import" element={<KeyImport />} />
        <Route path="/keys/:keyId" element={<KeyDetail />} />
        <Route path="/crypto" element={<CryptoPlayground />} />
        <Route path="/pools" element={<Pools />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/console" element={<RawConsole />} />
        <Route path="/admin/banks" element={<AdminBanks />} />
        <Route path="/admin/rbac" element={<AdminRBAC />} />
      </Route>
    </Routes>
  );
}
