import { ShieldCheck } from 'lucide-react';
import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@example.com');
  const [password, setPassword] = useState('Admin123!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-base-950 px-4">
      <form onSubmit={submit} className="w-full max-w-md rounded-lg border border-slate-800 bg-base-900 p-6 shadow-glow">
        <div className="mb-6 flex items-center gap-3">
          <span className="grid h-11 w-11 place-items-center rounded-lg bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/30">
            <ShieldCheck size={24} />
          </span>
          <div>
            <h1 className="text-lg font-semibold text-slate-50">Mini SIEM</h1>
            <p className="text-sm text-slate-400">Security Operations Console</p>
          </div>
        </div>
        <label className="mb-4 block">
          <span className="mb-1 block text-xs uppercase text-slate-500">Email</span>
          <input className="focus-ring w-full rounded-md border border-slate-700 bg-base-950 px-3 py-2 text-slate-100" value={email} onChange={(event) => setEmail(event.target.value)} />
        </label>
        <label className="mb-4 block">
          <span className="mb-1 block text-xs uppercase text-slate-500">Password</span>
          <input className="focus-ring w-full rounded-md border border-slate-700 bg-base-950 px-3 py-2 text-slate-100" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </label>
        {error && <p className="mb-4 rounded-md border border-red-500/30 bg-red-950/60 px-3 py-2 text-sm text-red-200">{error}</p>}
        <button disabled={loading} className="focus-ring w-full rounded-md bg-cyan-500 px-4 py-2 font-semibold text-base-950 hover:bg-cyan-400 disabled:opacity-60">
          {loading ? 'Signing in' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
