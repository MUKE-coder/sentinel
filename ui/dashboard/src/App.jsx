import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Threats from './pages/Threats';
import Actors from './pages/Actors';
import IPManagement from './pages/IPManagement';
import Performance from './pages/Performance';
import Users from './pages/Users';
import Alerts from './pages/Alerts';
import Audit from './pages/Audit';
import WAF from './pages/WAF';
import AIInsights from './pages/AIInsights';
import Analytics from './pages/Analytics';
import RateLimits from './pages/RateLimits';
import Reports from './pages/Reports';

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/sentinel/ui/login" replace />;
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      <Route
        path="/sentinel/ui/login"
        element={isAuthenticated ? <Navigate to="/sentinel/ui" replace /> : <Login />}
      />
      <Route
        path="/sentinel/ui"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="threats" element={<Threats />} />
        <Route path="actors" element={<Actors />} />
        <Route path="ip-management" element={<IPManagement />} />
        <Route path="performance" element={<Performance />} />
        <Route path="users" element={<Users />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="audit" element={<Audit />} />
        <Route path="waf" element={<WAF />} />
        <Route path="ai-insights" element={<AIInsights />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="rate-limits" element={<RateLimits />} />
        <Route path="reports" element={<Reports />} />
      </Route>
      <Route path="*" element={<Navigate to="/sentinel/ui" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}
