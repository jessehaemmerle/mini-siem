import type React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="grid min-h-screen place-items-center bg-base-950 text-slate-300">Loading</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}
