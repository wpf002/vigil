import React, {createContext, useContext, useEffect, useState, useCallback} from 'react';
import {clearTokens, decodeJwtPayload, getAccessToken} from '../api/client';
import type {User} from '../types';

interface AuthContextValue {
  authenticated: boolean;
  user: User | null;
  loading: boolean;
  setAuthenticated: (user: User) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({children}: {children: React.ReactNode}) {
  const [authenticated, setAuthFlag] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const token = await getAccessToken();
      if (!token) {
        setLoading(false);
        return;
      }
      const claims = await decodeJwtPayload(token);
      if (!claims) {
        setLoading(false);
        return;
      }
      const exp = claims.exp as number | undefined;
      if (exp && exp * 1000 < Date.now()) {
        setLoading(false);
        return;
      }
      setUser({
        user_id: String(claims.sub ?? ''),
        email: String(claims.email ?? ''),
        role: String(claims.role ?? 'analyst'),
        tenant_id: String(claims.tenant_id ?? ''),
      });
      setAuthFlag(true);
      setLoading(false);
    })();
  }, []);

  const setAuthenticated = useCallback((u: User) => {
    setUser(u);
    setAuthFlag(true);
  }, []);

  const signOut = useCallback(async () => {
    await clearTokens();
    setAuthFlag(false);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{authenticated, user, loading, setAuthenticated, signOut}}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return ctx;
}
