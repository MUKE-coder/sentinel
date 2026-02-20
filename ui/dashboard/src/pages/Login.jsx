import { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0f1e] flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-[#00d4ff] text-3xl font-bold tracking-widest">SENTINEL</h1>
          <p className="text-[#8892a0] text-sm mt-2">Security Dashboard</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-6 space-y-4">
          {error && (
            <div className="bg-[#ff2d5520] border border-[#ff2d5540] text-[#ff2d55] px-4 py-2 rounded text-sm">
              {error}
            </div>
          )}

          <div>
            <label className="block text-[#8892a0] text-xs uppercase tracking-wider mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-[#e0e0e0] text-sm focus:border-[#00d4ff] focus:outline-none transition-colors"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-[#8892a0] text-xs uppercase tracking-wider mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-[#e0e0e0] text-sm focus:border-[#00d4ff] focus:outline-none transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#00d4ff] text-[#0a0f1e] font-semibold py-2 rounded hover:bg-[#00b8e0] disabled:opacity-50 transition-colors text-sm"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
