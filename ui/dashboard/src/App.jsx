import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';

// Every page past the login screen is loaded on demand: the charting library
// alone is about half the bundle, and nobody needs all fifteen pages to see
// one. Login stays eager — it is the first screen.
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Threats = lazy(() => import('./pages/Threats'));
const Actors = lazy(() => import('./pages/Actors'));
const IPManagement = lazy(() => import('./pages/IPManagement'));
const Performance = lazy(() => import('./pages/Performance'));
const Users = lazy(() => import('./pages/Users'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Audit = lazy(() => import('./pages/Audit'));
const WAF = lazy(() => import('./pages/WAF'));
const AIInsights = lazy(() => import('./pages/AIInsights'));
const Analytics = lazy(() => import('./pages/Analytics'));
const RateLimits = lazy(() => import('./pages/RateLimits'));
const Reports = lazy(() => import('./pages/Reports'));
const CSPViolations = lazy(() => import('./pages/CSPViolations'));
const AuthShield = lazy(() => import('./pages/AuthShield'));

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/sentinel/ui/login" replace />;
}

function PageFallback() {
  return (
    <div className="flex items-center justify-center py-20 text-[#8892a0] text-sm">
      Loading…
    </div>
  );
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
        <Route path="csp" element={<CSPViolations />} />
        <Route path="auth-shield" element={<AuthShield />} />
      </Route>
      <Route path="*" element={<Navigate to="/sentinel/ui" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Suspense fallback={<PageFallback />}>
          <AppRoutes />
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  );
}
